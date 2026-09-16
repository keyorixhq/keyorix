package saml

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	csaml "github.com/crewjam/saml"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// FuzzParseResponseContent soaks Provider.ParseResponse from INSIDE the signature
// wall. FuzzParseResponse fuzzes the raw SAMLResponse bytes and asserts the
// signature-bypass invariant — but because the fuzzer holds no IdP key, virtually
// every mutation dies at the XML-DSig check, leaving the assertion-extraction and
// attribute-mapping code behind it almost dry.
//
// This harness pours past that wall: every iteration builds a FRESH, genuinely
// signed, IDP-initiated Response whose identity fields (NameID, email, common
// name, group) are the fuzzed input, then feeds it through ParseResponse exactly
// as a real ACS handler would. The signature is always valid, so the fuzzer's
// energy goes into the *content* — the NameID/attribute values that flow through
// XML encode → sign → C14N verify → decode → AssertionInfo mapping.
//
// Invariants:
//   - never panics / hangs (Guard);
//   - on error, no partial AssertionInfo escapes (nil info);
//   - identity round-trip: when a clean NameID was signed and the response is
//     accepted, the parsed Subject must equal exactly that NameID. A mismatch
//     means content the IdP signed for one field surfaced as another identity —
//     an assertion-extraction or attribute-confusion defect. (Restricted to a
//     whitespace-free, non-empty NameID so XML text-normalisation can't produce a
//     spurious inequality; other values still exercise the parser without the
//     equality assertion.)
func FuzzParseResponseContent(f *testing.F) {
	const idpEntityID = "https://idp.example/entity"
	const spEntityID = "https://keyorix.internal/saml/corp/metadata"
	const acsURL = "https://keyorix.internal/auth/saml/corp/acs"

	// --- signed IdP fixture: cert embedded in metadata == key used to sign ---
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "fuzz-idp-signing"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		f.Fatal(err)
	}
	idpCert, err := x509.ParseCertificate(der)
	if err != nil {
		f.Fatal(err)
	}
	idpMD := []byte(fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>%s</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, idpEntityID, base64.StdEncoding.EncodeToString(der)))

	p, err := NewProvider(Config{
		Name:              "corp",
		IDPMetadataXML:    idpMD,
		SPEntityID:        spEntityID,
		ACSURL:            acsURL,
		AllowIDPInitiated: true,
		EmailAttr:         "mail",
		NameAttr:          "cn",
		GroupsAttr:        "eduPersonAffiliation",
	})
	if err != nil {
		f.Fatal(err)
	}

	idpMetadataURL, err := url.Parse(idpEntityID)
	if err != nil {
		f.Fatal(err)
	}
	idp := &csaml.IdentityProvider{Key: priv, Certificate: idpCert, MetadataURL: *idpMetadataURL}
	spMetadata := p.sp.Metadata()

	var acsEndpoint *csaml.IndexedEndpoint
	var spssoDescriptor *csaml.SPSSODescriptor
	for i := range spMetadata.SPSSODescriptors {
		d := spMetadata.SPSSODescriptors[i]
		for j := range d.AssertionConsumerServices {
			ep := d.AssertionConsumerServices[j]
			if ep.Binding == csaml.HTTPPostBinding {
				acsEndpoint = &ep
				spssoDescriptor = &d
				break
			}
		}
		if acsEndpoint != nil {
			break
		}
	}
	if acsEndpoint == nil {
		f.Fatal("SP metadata advertises no HTTP-POST ACS endpoint")
	}

	// signResponse builds one fresh signed, IDP-initiated Response carrying the
	// given identity content. Returns ("", false) if the IdP-side construction
	// rejects the content (invalid XML chars etc.) — that's a fixture limitation,
	// not a keyorix defect, so the caller skips those inputs.
	signResponse := func(nameID, email, commonName, group string) (string, bool) {
		idpReq := &csaml.IdpAuthnRequest{
			IDP:                     idp,
			HTTPRequest:             httptest.NewRequest(http.MethodGet, "https://idp.example/sso", nil),
			RelayState:              "return-here",
			ServiceProviderMetadata: spMetadata,
			SPSSODescriptor:         spssoDescriptor,
			ACSEndpoint:             acsEndpoint,
			Now:                     time.Now(),
		}
		session := &csaml.Session{
			ID:             "sess-1",
			CreateTime:     time.Now(),
			ExpireTime:     time.Now().Add(time.Hour),
			NameID:         nameID,
			UserEmail:      email,
			UserCommonName: commonName,
			Groups:         []string{group},
		}
		if e := (csaml.DefaultAssertionMaker{}).MakeAssertion(idpReq, session); e != nil {
			return "", false
		}
		form, e := idpReq.PostBinding()
		if e != nil {
			return "", false
		}
		return form.SAMLResponse, true
	}

	f.Add("user@corp.example", "user@corp.example", "User Corp", "admins")
	f.Add("", "", "", "")
	f.Add("subject-only", "", "", "")
	f.Add("a b c", "e@x.io", "Common Name", "grp")

	f.Fuzz(func(t *testing.T, nameID, email, commonName, group string) {
		samlResponse, ok := signResponse(nameID, email, commonName, group)
		if !ok {
			return // IdP-side couldn't build a response for this content — skip
		}

		body := url.Values{"SAMLResponse": {samlResponse}}.Encode()
		req := httptest.NewRequest(http.MethodPost, acsURL, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := req.ParseForm(); err != nil {
			return
		}

		var info *AssertionInfo
		var perr error
		fuzzutil.Guard(t.Fatalf, "saml.Provider.ParseResponse(content)", func() {
			info, perr = p.ParseResponse(req, nil)
		})

		if perr != nil {
			if info != nil {
				t.Fatalf("ParseResponse returned an error but a non-nil AssertionInfo (partial success): %+v err=%v", info, perr)
			}
			return
		}
		if info == nil {
			t.Fatalf("ParseResponse returned nil error but nil AssertionInfo")
		}
		// Identity round-trip. Only assert for a clean NameID so XML text handling
		// (surrounding whitespace, empty text) can't yield a spurious mismatch; the
		// other inputs still soak the parser above.
		if nameID != "" && nameID == strings.TrimSpace(nameID) {
			if info.Subject != nameID {
				t.Fatalf("IDENTITY MISMATCH: signed NameID %q but ParseResponse returned Subject %q (email=%q name=%q groups=%v)", nameID, info.Subject, info.Email, info.Name, info.Groups)
			}
		}
	})
}

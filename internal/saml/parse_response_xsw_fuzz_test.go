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

// FuzzParseResponseXSW is the structure-aware XML-signature-wrapping (XSW)
// differential for Provider.ParseResponse. FuzzParseResponse fuzzes raw bytes and
// asserts a byte-level bypass invariant; that found the trailing-epilogue variant,
// but XSW is a FAMILY (assertion wrapping, sibling injection, comment-truncation
// via C14N, duplicate IDs). This harness starts from a genuinely signed response
// and applies fuzz-directed STRUCTURAL mutations to it, then asserts the one
// property that must hold across every variant:
//
//	ParseResponse either rejects (error), or returns EXACTLY the signed identity.
//
// Any success whose Subject differs from the signed NameID is an XSW bypass — an
// injected/duplicated assertion was trusted, or a comment split the NameID so a
// different identity was read out of a still-valid signature. The signed subject
// is the only legitimate success, so this has no false positives: a mutation that
// crewjam correctly rejects errors out (fine), and one it correctly ignores still
// yields the signed subject (fine).
func FuzzParseResponseXSW(f *testing.F) {
	const (
		idpEntityID     = "https://idp.example/entity"
		spEntityID      = "https://keyorix.internal/saml/corp/metadata"
		acsURL          = "https://keyorix.internal/auth/saml/corp/acs"
		originalSubject = "user@corp.example"
		evilSubject     = "xsw-attacker@evil.example" // must differ from originalSubject
	)

	// --- signed IdP fixture: cert embedded in metadata == key used to sign ---
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "xsw-idp-signing"},
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
		Name: "corp", IDPMetadataXML: idpMD, SPEntityID: spEntityID, ACSURL: acsURL,
		AllowIDPInitiated: true, EmailAttr: "mail", NameAttr: "cn", GroupsAttr: "eduPersonAffiliation",
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
	idpReq := &csaml.IdpAuthnRequest{
		IDP: idp, HTTPRequest: httptest.NewRequest(http.MethodGet, "https://idp.example/sso", nil),
		RelayState: "return-here", ServiceProviderMetadata: spMetadata,
		SPSSODescriptor: spssoDescriptor, ACSEndpoint: acsEndpoint, Now: time.Now(),
	}
	session := &csaml.Session{
		ID: "sess-1", CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour),
		NameID: originalSubject, UserEmail: originalSubject, UserCommonName: "User Corp",
		Groups: []string{"admins"},
	}
	if err := (csaml.DefaultAssertionMaker{}).MakeAssertion(idpReq, session); err != nil {
		f.Fatal(err)
	}
	form, err := idpReq.PostBinding()
	if err != nil {
		f.Fatal(err)
	}
	signedXML, err := base64.StdEncoding.DecodeString(form.SAMLResponse)
	if err != nil {
		f.Fatal(err)
	}

	// An unsigned attacker assertion asserting a different identity — the payload a
	// wrapping/injection variant tries to get the SP to read instead of the signed one.
	evilAssertion := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0" ID="_evil" IssueInstant="2024-01-01T00:00:00Z"><saml:Issuer>` + idpEntityID + `</saml:Issuer><saml:Subject><saml:NameID>` + evilSubject + `</saml:NameID></saml:Subject><saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"/><saml:AuthnStatement AuthnInstant="2024-01-01T00:00:00Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion>`

	f.Add(uint8(0), uint16(0), []byte(""))
	f.Add(uint8(0), uint16(len(signedXML)/2), []byte("x"))                       // comment mid-document
	f.Add(uint8(2), uint16(len(signedXML)-len("</samlp:Response>")), []byte("")) // evil assertion near end
	f.Add(uint8(1), uint16(0), []byte("<x/>"))

	f.Fuzz(func(t *testing.T, op uint8, off uint16, blob []byte) {
		x := string(signedXML)
		o := int(off) % (len(x) + 1)
		switch op % 3 {
		case 0:
			// Comment splice — exercises C14N comment handling / comment-truncation:
			// a comment placed inside the signed NameID leaves the signature valid
			// (exclusive-C14N strips comments) but can split the text a naive reader sees.
			x = x[:o] + "<!--" + strings.ReplaceAll(string(blob), "--", "") + "-->" + x[o:]
		case 1:
			x = x[:o] + string(blob) + x[o:] // raw structural injection
		case 2:
			x = x[:o] + evilAssertion + x[o:] // wrapped / sibling evil assertion
		}

		body := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(x))}}.Encode()
		req := httptest.NewRequest(http.MethodPost, acsURL, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := req.ParseForm(); err != nil {
			return
		}

		var info *AssertionInfo
		var perr error
		fuzzutil.Guard(t.Fatalf, "saml.ParseResponse.XSW", func() {
			info, perr = p.ParseResponse(req, nil)
		})
		if perr != nil {
			return // correctly rejected — the safe outcome for a tampered response
		}
		if info == nil {
			t.Fatalf("ParseResponse returned nil error but nil AssertionInfo (op=%d off=%d)", op, off)
		}
		if info.Subject != originalSubject {
			t.Fatalf("SAML XSW BYPASS: mutated response verified with subject %q, but only the signed subject %q may verify (op=%d off=%d)", info.Subject, originalSubject, op, off)
		}
	})
}

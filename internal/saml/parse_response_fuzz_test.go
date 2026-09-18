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

// FuzzParseResponse fuzzes Provider.ParseResponse, the ACS entry point that turns
// an IdP's SAMLResponse form field — fully attacker-controlled bytes posted to the
// ACS URL — into an authenticated AssertionInfo. FuzzSAMLMetadata already covers
// the IdP-metadata parse; this covers the far more sensitive response path: XML
// decode, XML-DSig verification against the pinned IdP cert, condition/audience
// checks, and assertion extraction.
//
// This is a walled target (crewjam/saml rejects anything without a valid XML-DSig
// signature over the pinned cert), so a naive byte fuzzer would never get past the
// signature check. The harness starts INSIDE the wall: setup builds a real signed,
// IDP-initiated Response with an IdP key the SP trusts (mirroring
// TestParseResponse_Success), seeds the corpus with it, and lets the fuzzer mutate
// from there.
//
// Invariants:
//   - never panics / hangs (Guard);
//   - on error, no partial AssertionInfo escapes (nil info);
//   - SIGNATURE-BYPASS: the fuzzer never holds the IdP private key, so the ONLY
//     input that may legitimately verify is the exact response this harness signed.
//     A success (nil error, non-nil info) on any OTHER input means a signature was
//     accepted that we never produced — an XML signature-wrapping/canonicalization
//     bypass, an unsigned-assertion acceptance, or a stripped-signature path.
//   - ERROR-ORACLE SANITIZATION: every failing input must return the exact fixed
//     sentinel errInvalidSAMLResponse — never a distinguishable error whose text or
//     type varies with the internal failure reason. The ACS body is fully
//     attacker-controlled and unauthenticated, so any per-reason variation in the
//     returned error is an oracle: crewjam's InvalidResponseError.PrivateErr carries
//     XML-parse / signature / certificate internals, and — on the SAML decrypt path
//     specifically — a CBC EncryptedAssertion has no authentication tag, so a
//     reason-distinguishing error there is a padding oracle by construction. Keyorix
//     configures no SP decryption key, so an EncryptedAssertion cannot decrypt at all
//     and must fail closed through the SAME sanitized sentinel; this invariant locks
//     that (and every other failure path) against arbitrary input. A correct
//     ParseResponse satisfies it by construction — it returns errInvalidSAMLResponse
//     bare on both of its error paths — so asserting identity here false-positives on
//     nothing and catches any future path that leaks a distinguishable error.
//     (Note: the raw xmlenc CBC cipher's own padding behaviour is NOT asserted here or
//     anywhere — it is unauthenticated, so its padding IS an oracle by design; the
//     mitigation is architectural, the outer XML-DSig verified before decrypt and this
//     sanitized-error boundary, not the cipher. See FuzzXMLEncGCMIntegrity's note.)
func FuzzParseResponse(f *testing.F) {
	const idpEntityID = "https://idp.example/entity"
	const spEntityID = "https://keyorix.internal/saml/corp/metadata"
	const acsURL = "https://keyorix.internal/auth/saml/corp/acs"

	// --- signed IdP fixture: cert embedded in metadata == key used to sign below ---
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

	// --- build one genuinely valid, signed, IDP-initiated Response ---
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
		NameID:         "user@corp.example",
		UserEmail:      "user@corp.example",
		UserCommonName: "User Corp",
		Groups:         []string{"admins", "devs"},
	}
	if err := (csaml.DefaultAssertionMaker{}).MakeAssertion(idpReq, session); err != nil {
		f.Fatal(err)
	}
	form, err := idpReq.PostBinding()
	if err != nil {
		f.Fatal(err)
	}
	validResponse := form.SAMLResponse

	// Seeds: the valid response plus malformed neighbours.
	f.Add(validResponse)
	f.Add("")
	f.Add("not-valid-base64-!!!")
	f.Add(base64.StdEncoding.EncodeToString([]byte("<samlp:Response/>")))
	f.Add(base64.StdEncoding.EncodeToString([]byte("not xml")))
	if len(validResponse) > 16 {
		f.Add(validResponse[:len(validResponse)-8]) // truncated
		f.Add(validResponse + "QUFB")               // trailing garbage
	}
	// Fail-closed EncryptedAssertion seeds: keyorix configures no SP decryption key,
	// so a CBC EncryptedAssertion must fail through the sanitized sentinel — never a
	// decrypt/padding error that varies with the (unauthenticated) ciphertext. These
	// drive the mutator onto the decrypt branch of crewjam's ParseResponse.
	f.Add(base64.StdEncoding.EncodeToString([]byte(
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
			`<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
			`<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">` +
			`<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>` +
			`<xenc:CipherData><xenc:CipherValue>AAAAAAAAAAAAAAAAAAAAAA==</xenc:CipherValue></xenc:CipherData>` +
			`</xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>`)))
	f.Add(base64.StdEncoding.EncodeToString([]byte(
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">` +
			`<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
			`<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">` +
			`<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/>` +
			`<xenc:CipherData><xenc:CipherValue>Zm9vYmFyYmF6</xenc:CipherValue></xenc:CipherData>` +
			`</xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>`)))

	f.Fuzz(func(t *testing.T, samlResponse string) {
		// Submit exactly as a real ACS handler does: form-encoded POST, ParseForm
		// first (crewjam reads req.PostForm, not req.PostFormValue).
		body := url.Values{"SAMLResponse": {samlResponse}}.Encode()
		req := httptest.NewRequest(http.MethodPost, acsURL, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := req.ParseForm(); err != nil {
			return // malformed form encoding is not what this target exercises
		}

		var info *AssertionInfo
		var perr error
		fuzzutil.Guard(t.Fatalf, "saml.Provider.ParseResponse", func() {
			info, perr = p.ParseResponse(req, nil)
		})

		if perr != nil {
			if info != nil {
				t.Fatalf("ParseResponse returned an error but a non-nil AssertionInfo (partial success): %+v err=%v", info, perr)
			}
			// ERROR-ORACLE SANITIZATION invariant: the caller must never be able to
			// tell WHY a response failed. Every error path returns the exact same
			// sentinel; identity equality (not errors.Is) is deliberate — a future
			// path that wraps the sentinel with distinguishing text would satisfy
			// errors.Is yet still leak an oracle, so we require the bare sentinel.
			if perr != errInvalidSAMLResponse {
				t.Fatalf("ERROR-ORACLE LEAK: ParseResponse returned a distinguishable error instead of the fixed sanitized sentinel; caller can infer the internal failure reason: %q (type %T)", perr.Error(), perr)
			}
			return
		}
		if info == nil {
			t.Fatalf("ParseResponse returned nil error but nil AssertionInfo")
		}
		// Signature-bypass invariant: only the exact response the harness signed may
		// verify. Any other accepted input is a forged/wrapped/stripped signature.
		if samlResponse != validResponse {
			t.Fatalf("SAML SIGNATURE BYPASS: ParseResponse accepted a response the harness never signed (subject=%q email=%q groups=%v)", info.Subject, info.Email, info.Groups)
		}
	})
}

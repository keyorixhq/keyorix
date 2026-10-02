// Package samltest builds real, cryptographically-signed SAML IdP fixtures for code
// outside internal/saml that needs to drive (*saml.Provider).ParseResponse's actual
// signature-verification path — not a stub — e.g. server/faultops' real-transport
// fuzz harness. Mirrors internal/saml/parse_response_success_test.go's own fixture
// construction (signedIDPFixture + TestParseResponse_Success's IdP-side assertion/
// response building) using crewjam/saml's own IdP-side machinery (the same code path
// its own test suite uses), so a validating SP sees a signature a genuine IdP would
// also produce, not a hand-rolled approximation.
//
// Not a _test.go file (so importable from another package's test code), but
// exists ONLY to support tests — no production code should import this package.
package samltest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"time"

	csaml "github.com/crewjam/saml"
)

// IdPFixture is a self-signed RSA signing key/cert pair plus the IdP metadata XML
// that embeds the certificate as the signing certificate — the fixture an SP's
// Config.IDPMetadataXML trusts, paired with the key needed to sign a Response that
// SP will accept.
type IdPFixture struct {
	MetadataXML []byte
	Key         *rsa.PrivateKey
	Cert        *x509.Certificate
}

// NewIdPFixture builds a self-signed IdP signing key/cert and the metadata XML
// advertising it, identical in shape to internal/saml's own signedIDPFixture
// (parse_response_success_test.go).
func NewIdPFixture(entityID string) (*IdPFixture, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("samltest: generate IdP signing key: %w", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "fuzz-idp-signing"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("samltest: create IdP signing cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("samltest: parse IdP signing cert: %w", err)
	}
	certB64 := base64.StdEncoding.EncodeToString(der)
	md := []byte(fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>%s</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://fuzz-idp.invalid/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, entityID, certB64))
	return &IdPFixture{MetadataXML: md, Key: priv, Cert: cert}, nil
}

// SignedResponse builds a real, IDP-initiated, signed SAML Response asserting the
// given identity against spMetadata's first HTTP-POST ACS endpoint, using fixture's
// key/cert — the same crewjam/saml IdP-side machinery (IdpAuthnRequest +
// DefaultAssertionMaker + PostBinding) internal/saml's own ParseResponse success
// test uses, so a validating SP exercises the real signature path, not a stub.
// Returns the base64 SAMLResponse form value exactly as a real IdP POST would carry it.
func SignedResponse(fixture *IdPFixture, idpEntityID string, spMetadata *csaml.EntityDescriptor, nameID, email, name string, groups []string, relayState string) (string, error) {
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
		return "", errors.New("samltest: SP metadata advertises no HTTP-POST ACS endpoint")
	}

	idpMetadataURL, err := neturl.Parse(idpEntityID)
	if err != nil {
		return "", fmt.Errorf("samltest: parse idpEntityID: %w", err)
	}
	idp := &csaml.IdentityProvider{Key: fixture.Key, Certificate: fixture.Cert, MetadataURL: *idpMetadataURL}

	httpReq := httptest.NewRequest(http.MethodGet, "https://fuzz-idp.invalid/sso", nil)
	idpReq := &csaml.IdpAuthnRequest{
		IDP: idp, HTTPRequest: httpReq, RelayState: relayState,
		ServiceProviderMetadata: spMetadata, SPSSODescriptor: spssoDescriptor,
		ACSEndpoint: acsEndpoint, Now: time.Now(),
	}
	session := &csaml.Session{
		ID: "fuzz-" + relayState, CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour),
		NameID: nameID, UserEmail: email, UserCommonName: name, Groups: groups,
	}
	if err := (csaml.DefaultAssertionMaker{}).MakeAssertion(idpReq, session); err != nil {
		return "", fmt.Errorf("samltest: MakeAssertion: %w", err)
	}
	form, err := idpReq.PostBinding()
	if err != nil {
		return "", fmt.Errorf("samltest: PostBinding: %w", err)
	}
	return form.SAMLResponse, nil
}

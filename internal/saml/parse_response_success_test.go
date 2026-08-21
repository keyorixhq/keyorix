package saml

// parse_response_success_test.go exercises the one remaining meaningfully-testable gap
// in ParseResponse: the success path (the final `return extractAssertion(assertion, ...),
// nil` line). Doing that for real — not with a stub — requires a genuinely valid, signed
// SAML Response: crewjam/saml validates the XML-DSig signature against the pinned IdP
// certificate, so nothing short of a real signature will do.
//
// crewjam/saml ships a full SAML Identity Provider implementation (identity_provider.go)
// used by its own test suite to produce exactly this kind of fixture. This file drives
// that IDP-side machinery directly (bypassing the HTTP handlers, which need a
// SessionProvider/ServiceProviderProvider) to build one signed, IDP-initiated Response —
// signed with the SAME private key embedded as the signing certificate in the IdP
// metadata handed to our Provider — then feeds it through the public Provider.ParseResponse
// exactly as a real ACS handler would (after calling r.ParseForm(), which crewjam's
// ParseResponse relies on the caller having done: it reads req.PostForm, not
// req.PostFormValue, and never parses the form itself).

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signedIDPFixture builds a self-signed RSA cert/key pair and the IdP metadata XML that
// embeds it as the signing certificate — the same shape as idpMetadata(t) in
// provider_test.go, except it also returns the private key and certificate so a caller
// can sign a Response with the exact key the SP will trust.
func signedIDPFixture(t *testing.T, entityID string) (metadataXML []byte, key *rsa.PrivateKey, cert *x509.Certificate) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test-idp-signing"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	parsedCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	certB64 := base64.StdEncoding.EncodeToString(der)

	md := []byte(fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>%s</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, entityID, certB64))

	return md, priv, parsedCert
}

// TestParseResponse_Success builds a real, signed, IDP-initiated SAML Response using
// crewjam/saml's own IdP-side assertion/response construction (the same code path its
// own test suite uses to produce fixtures), submits it to Provider.ParseResponse exactly
// as a real ACS handler would, and asserts the returned AssertionInfo reflects the
// session attributes — exercising the success return line that every other ParseResponse
// test necessarily leaves uncovered.
func TestParseResponse_Success(t *testing.T) {
	const idpEntityID = "https://idp.example/entity"
	const spEntityID = "https://keyorix.internal/saml/corp/metadata"
	const acsURL = "https://keyorix.internal/auth/saml/corp/acs"

	idpMD, idpKey, idpCert := signedIDPFixture(t, idpEntityID)

	p, err := NewProvider(Config{
		Name:              "corp",
		IDPMetadataXML:    idpMD,
		SPEntityID:        spEntityID,
		ACSURL:            acsURL,
		AllowIDPInitiated: true,
		// Match crewjam's DefaultAssertionMaker attribute FriendlyNames so the mapped
		// AssertionInfo below reflects real session data, not just an empty struct.
		EmailAttr:  "mail",
		NameAttr:   "cn",
		GroupsAttr: "eduPersonAffiliation",
	})
	require.NoError(t, err)

	// Build the IdP side: an IdentityProvider whose signing key/cert are exactly the
	// ones embedded in idpMD above, so the SP's signature check succeeds.
	idpMetadataURL, err := url.Parse(idpEntityID)
	require.NoError(t, err)
	idp := &csaml.IdentityProvider{
		Key:         idpKey,
		Certificate: idpCert,
		MetadataURL: *idpMetadataURL,
	}

	// req.ServiceProviderMetadata is exactly what our own SP would publish — pull it
	// straight from the Provider under test rather than re-deriving it, so the fixture
	// can't silently drift from what NewProvider actually built.
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
	require.NotNil(t, acsEndpoint, "SP metadata must advertise an HTTP-POST ACS endpoint")

	httpReq := httptest.NewRequest(http.MethodGet, "https://idp.example/sso", nil)

	idpReq := &csaml.IdpAuthnRequest{
		IDP:                     idp,
		HTTPRequest:             httpReq,
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

	require.NoError(t, csaml.DefaultAssertionMaker{}.MakeAssertion(idpReq, session),
		"building the IdP-side assertion must succeed")

	form, err := idpReq.PostBinding()
	require.NoError(t, err, "signing and serializing the Response must succeed")
	require.NotEmpty(t, form.SAMLResponse)

	// Submit exactly as a real ACS handler would: POST the base64 Response as
	// application/x-www-form-urlencoded, and call ParseForm() first — crewjam's
	// ParseResponse reads req.PostForm (not req.PostFormValue), so an un-parsed form
	// would read back empty regardless of the body, which is not what we're testing here.
	body := url.Values{"SAMLResponse": {form.SAMLResponse}}.Encode()
	acsReq := httptest.NewRequest(http.MethodPost, acsURL, strings.NewReader(body))
	acsReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, acsReq.ParseForm())

	info, err := p.ParseResponse(acsReq, nil)
	require.NoError(t, err, "a validly signed, IDP-initiated response must be accepted")
	require.NotNil(t, info)

	assert.Equal(t, "user@corp.example", info.Subject)
	assert.Equal(t, "user@corp.example", info.Email)
	assert.Equal(t, "User Corp", info.Name)
	assert.ElementsMatch(t, []string{"admins", "devs"}, info.Groups)
}

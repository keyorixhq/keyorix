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
	"strings"
	"testing"
	"time"

	csaml "github.com/crewjam/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// idpMetadata builds valid IdP SAML metadata with a self-signed signing cert and an
// HTTP-Redirect SSO binding, for the construction/metadata/authn-request tests.
func idpMetadata(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert := base64.StdEncoding.EncodeToString(der)

	return []byte(fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example/entity">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>%s</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, cert))
}

func testProvider(t *testing.T) *Provider {
	t.Helper()
	p, err := NewProvider(Config{
		Name:           "corp",
		IDPMetadataXML: idpMetadata(t),
		SPEntityID:     "https://keyorix.internal/saml/corp/metadata",
		ACSURL:         "https://keyorix.internal/auth/saml/corp/acs",
	})
	require.NoError(t, err)
	return p
}

func TestNewProvider_Validation(t *testing.T) {
	md := idpMetadata(t)
	_, err := NewProvider(Config{IDPMetadataXML: md, ACSURL: "https://x/acs"})
	require.ErrorContains(t, err, "sp_entity_id")

	_, err = NewProvider(Config{IDPMetadataXML: md, SPEntityID: "https://x"})
	require.ErrorContains(t, err, "acs_url")

	_, err = NewProvider(Config{IDPMetadataXML: []byte("not xml"), SPEntityID: "https://x", ACSURL: "https://x/acs"})
	require.Error(t, err, "bad metadata is rejected")
}

func TestProvider_Metadata(t *testing.T) {
	md, err := testProvider(t).Metadata()
	require.NoError(t, err)
	s := string(md)
	assert.Contains(t, s, "https://keyorix.internal/auth/saml/corp/acs", "SP metadata advertises the ACS URL")
	assert.Contains(t, s, "EntityDescriptor")
}

func TestProvider_AuthnRequest(t *testing.T) {
	redirect, reqID, err := testProvider(t).AuthnRequest("return-here")
	require.NoError(t, err)
	assert.NotEmpty(t, reqID, "the request ID is returned for InResponseTo matching")
	assert.Contains(t, redirect, "https://idp.example/sso", "redirects to the IdP SSO location")
	assert.Contains(t, redirect, "SAMLRequest=", "carries the encoded AuthnRequest")
	assert.Contains(t, redirect, "RelayState=return-here")
}

func TestExtractAssertion(t *testing.T) {
	a := &csaml.Assertion{
		Subject: &csaml.Subject{NameID: &csaml.NameID{Value: "user@corp.example"}},
		AttributeStatements: []csaml.AttributeStatement{{Attributes: []csaml.Attribute{
			{Name: defaultEmailAttr, Values: []csaml.AttributeValue{{Value: "user@corp.example"}}},
			{Name: defaultNameAttr, Values: []csaml.AttributeValue{{Value: "User Corp"}}},
			{Name: defaultGroupsAttr, Values: []csaml.AttributeValue{{Value: "admins"}, {Value: "  "}, {Value: "devs"}}},
		}}},
	}
	info := extractAssertion(a, defaultEmailAttr, defaultNameAttr, defaultGroupsAttr)
	assert.Equal(t, "user@corp.example", info.Subject)
	assert.Equal(t, "user@corp.example", info.Email)
	assert.Equal(t, "User Corp", info.Name)
	assert.Equal(t, []string{"admins", "devs"}, info.Groups, "blank group values are dropped")
}

func TestExtractAssertion_FriendlyNameAndMissing(t *testing.T) {
	// Match by FriendlyName, and tolerate a missing subject / attributes.
	a := &csaml.Assertion{
		AttributeStatements: []csaml.AttributeStatement{{Attributes: []csaml.Attribute{
			{FriendlyName: "mail", Values: []csaml.AttributeValue{{Value: "a@b.com"}}},
		}}},
	}
	info := extractAssertion(a, "mail", "displayName", "groups")
	assert.Equal(t, "a@b.com", info.Email)
	assert.Empty(t, info.Subject)
	assert.Empty(t, info.Name)
	assert.Empty(t, info.Groups)
}

// requireAudienceRestriction is the ValidateAudienceRestriction hook wired into every
// Provider's ServiceProvider (see NewProvider). The underlying crewjam/saml library
// treats an assertion with NO AudienceRestriction as vacuously valid — this pins that
// our override closes that gap: a missing element is a hard failure, a mismatched
// element is a hard failure, and a matching element passes.
func TestRequireAudienceRestriction(t *testing.T) {
	const us = "https://keyorix.internal/saml/corp/metadata"
	check := requireAudienceRestriction(us)

	t.Run("no AudienceRestriction is rejected", func(t *testing.T) {
		a := &csaml.Assertion{Conditions: &csaml.Conditions{}}
		err := check(a)
		require.Error(t, err, "an assertion with zero AudienceRestrictions must be rejected, not vacuously accepted")
	})

	t.Run("nil Conditions is rejected", func(t *testing.T) {
		a := &csaml.Assertion{}
		require.Error(t, check(a))
	})

	t.Run("nil assertion is rejected", func(t *testing.T) {
		require.Error(t, check(nil))
	})

	t.Run("mismatched Audience is rejected", func(t *testing.T) {
		a := &csaml.Assertion{Conditions: &csaml.Conditions{
			AudienceRestrictions: []csaml.AudienceRestriction{{Audience: csaml.Audience{Value: "https://someone-else.example/sp"}}},
		}}
		require.Error(t, check(a))
	})

	t.Run("matching Audience passes", func(t *testing.T) {
		a := &csaml.Assertion{Conditions: &csaml.Conditions{
			AudienceRestrictions: []csaml.AudienceRestriction{{Audience: csaml.Audience{Value: us}}},
		}}
		require.NoError(t, check(a))
	})

	t.Run("one matching among several passes", func(t *testing.T) {
		a := &csaml.Assertion{Conditions: &csaml.Conditions{
			AudienceRestrictions: []csaml.AudienceRestriction{
				{Audience: csaml.Audience{Value: "https://someone-else.example/sp"}},
				{Audience: csaml.Audience{Value: us}},
			},
		}}
		require.NoError(t, check(a))
	})
}

// NewProvider must wire requireAudienceRestriction into the underlying
// ServiceProvider so the override actually takes effect end-to-end, not just exist
// as an unused helper.
func TestNewProvider_WiresAudienceRestrictionOverride(t *testing.T) {
	p := testProvider(t)
	require.NotNil(t, p.sp.ValidateAudienceRestriction, "ValidateAudienceRestriction must be overridden")

	// An assertion with no AudienceRestriction must be rejected by the wired hook.
	err := p.sp.ValidateAudienceRestriction(&csaml.Assertion{Conditions: &csaml.Conditions{}})
	require.Error(t, err)
}

// ParseResponse must never reflect the underlying crewjam/saml library's error text
// back to the caller — that text (and especially InvalidResponseError.PrivateErr) can
// carry internal detail never meant for the untrusted caller of a public ACS endpoint.
// Every failure collapses to the same fixed, generic error.
func TestParseResponse_SanitizesLibraryError(t *testing.T) {
	p := testProvider(t)
	req := httptest.NewRequest(http.MethodPost, "https://keyorix.internal/auth/saml/corp/acs", strings.NewReader("SAMLResponse=not-valid-base64!!"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := p.ParseResponse(req, []string{"req-id"})
	require.Error(t, err)
	assert.Same(t, errInvalidSAMLResponse, err, "the caller must get the fixed sanitized error, not the library's own error text")
	assert.NotContains(t, err.Error(), "base64", "the library's internal error detail must not leak into the returned error")
}

func TestParseIDPMetadata_Errors(t *testing.T) {
	_, err := parseIDPMetadata(nil)
	require.ErrorContains(t, err, "empty")

	// Well-formed metadata but with only an SPSSODescriptor (no IdP role) is rejected.
	spOnly := []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"></SPSSODescriptor>
</EntityDescriptor>`)
	_, err = parseIDPMetadata(spOnly)
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "IDPSSODescriptor"))
}

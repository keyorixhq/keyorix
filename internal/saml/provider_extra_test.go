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

// TestOrDefault validates the fallback helper.
func TestOrDefault(t *testing.T) {
	assert.Equal(t, "fallback", orDefault("", "fallback"))
	assert.Equal(t, "fallback", orDefault("   ", "fallback"))
	assert.Equal(t, "explicit", orDefault("explicit", "fallback"))
	assert.Equal(t, "x", orDefault("x", "y"))
}

// TestAttrMatches_ByName validates Name-based matching.
func TestAttrMatches_ByName(t *testing.T) {
	attr := csaml.Attribute{Name: "email"}
	assert.True(t, attrMatches(attr, "email"))
	assert.False(t, attrMatches(attr, "EMAIL"))
	assert.False(t, attrMatches(attr, "other"))
}

// TestAttrMatches_ByFriendlyName validates case-insensitive FriendlyName matching.
func TestAttrMatches_ByFriendlyName(t *testing.T) {
	attr := csaml.Attribute{FriendlyName: "DisplayName"}
	assert.True(t, attrMatches(attr, "displayname"))
	assert.True(t, attrMatches(attr, "DISPLAYNAME"))
	assert.True(t, attrMatches(attr, "DisplayName"))
	assert.False(t, attrMatches(attr, "email"))
}

// TestAttributeValues_TrimsAndFiltersBlank validates that blank values are
// stripped and non-blank ones are preserved.
func TestAttributeValues_TrimsAndFiltersBlank(t *testing.T) {
	attr := csaml.Attribute{
		Values: []csaml.AttributeValue{
			{Value: "  admins  "},
			{Value: ""},
			{Value: "   "},
			{Value: "devs"},
		},
	}
	vals := attributeValues(attr)
	require.Len(t, vals, 2)
	assert.Equal(t, "admins", vals[0])
	assert.Equal(t, "devs", vals[1])
}

// TestAttributeValues_Empty validates that an attribute with no values returns
// an empty slice.
func TestAttributeValues_Empty(t *testing.T) {
	attr := csaml.Attribute{Values: nil}
	assert.Empty(t, attributeValues(attr))
}

// TestExtractAssertion_NilSubject validates that a nil Subject doesn't panic.
func TestExtractAssertion_NilSubject(t *testing.T) {
	a := &csaml.Assertion{
		// Subject intentionally nil
		AttributeStatements: []csaml.AttributeStatement{{
			Attributes: []csaml.Attribute{
				{Name: defaultEmailAttr, Values: []csaml.AttributeValue{{Value: "user@example.com"}}},
			},
		}},
	}
	info := extractAssertion(a, defaultEmailAttr, defaultNameAttr, defaultGroupsAttr)
	assert.Empty(t, info.Subject, "nil Subject must not panic")
	assert.Equal(t, "user@example.com", info.Email)
}

// TestExtractAssertion_NilNameID validates that a nil NameID doesn't panic.
func TestExtractAssertion_NilNameID(t *testing.T) {
	a := &csaml.Assertion{
		Subject: &csaml.Subject{NameID: nil},
	}
	info := extractAssertion(a, defaultEmailAttr, defaultNameAttr, defaultGroupsAttr)
	assert.Empty(t, info.Subject)
}

// TestExtractAssertion_NoAttributeStatements validates extraction with no
// attribute statements.
func TestExtractAssertion_NoAttributeStatements(t *testing.T) {
	a := &csaml.Assertion{
		Subject: &csaml.Subject{NameID: &csaml.NameID{Value: "uid=alice"}},
	}
	info := extractAssertion(a, defaultEmailAttr, defaultNameAttr, defaultGroupsAttr)
	assert.Equal(t, "uid=alice", info.Subject)
	assert.Empty(t, info.Email)
	assert.Empty(t, info.Name)
	assert.Empty(t, info.Groups)
}

// TestExtractAssertion_MultipleGroups validates that multiple group values are
// all accumulated.
func TestExtractAssertion_MultipleGroups(t *testing.T) {
	a := &csaml.Assertion{
		AttributeStatements: []csaml.AttributeStatement{{
			Attributes: []csaml.Attribute{
				{
					Name: defaultGroupsAttr,
					Values: []csaml.AttributeValue{
						{Value: "group1"},
						{Value: "group2"},
						{Value: "group3"},
					},
				},
			},
		}},
	}
	info := extractAssertion(a, defaultEmailAttr, defaultNameAttr, defaultGroupsAttr)
	assert.Equal(t, []string{"group1", "group2", "group3"}, info.Groups)
}

// TestExtractAssertion_MultipleStatements validates that attribute statements
// across multiple AttributeStatement elements are all considered.
func TestExtractAssertion_MultipleStatements(t *testing.T) {
	a := &csaml.Assertion{
		AttributeStatements: []csaml.AttributeStatement{
			{Attributes: []csaml.Attribute{
				{Name: defaultEmailAttr, Values: []csaml.AttributeValue{{Value: "a@b.com"}}},
			}},
			{Attributes: []csaml.Attribute{
				{Name: defaultNameAttr, Values: []csaml.AttributeValue{{Value: "Alice"}}},
			}},
		},
	}
	info := extractAssertion(a, defaultEmailAttr, defaultNameAttr, defaultGroupsAttr)
	assert.Equal(t, "a@b.com", info.Email)
	assert.Equal(t, "Alice", info.Name)
}

// TestParseIDPMetadata_EmptyInput validates that nil/empty metadata is rejected.
func TestParseIDPMetadata_EmptyInput(t *testing.T) {
	_, err := parseIDPMetadata(nil)
	require.ErrorContains(t, err, "empty")

	_, err = parseIDPMetadata([]byte{})
	require.ErrorContains(t, err, "empty")

	_, err = parseIDPMetadata([]byte("   \n\t  "))
	require.ErrorContains(t, err, "empty")
}

// TestParseIDPMetadata_ValidMetadata validates that well-formed IdP metadata is
// accepted by the same helper used in production.
func TestParseIDPMetadata_ValidMetadata(t *testing.T) {
	md := idpMetadata(t) // from provider_test.go helper
	entity, err := parseIDPMetadata(md)
	require.NoError(t, err)
	require.NotNil(t, entity)
	assert.Equal(t, "https://idp.example/entity", entity.EntityID)
	assert.NotEmpty(t, entity.IDPSSODescriptors)
}

// TestNewProvider_DefaultAttributes validates that missing EmailAttr/NameAttr/
// GroupsAttr fields fall back to the documented Azure AD defaults.
func TestNewProvider_DefaultAttributes(t *testing.T) {
	p, err := NewProvider(Config{
		Name:           "corp",
		IDPMetadataXML: idpMetadata(t),
		SPEntityID:     "https://sp.example/metadata",
		ACSURL:         "https://sp.example/acs",
		// EmailAttr/NameAttr/GroupsAttr left empty → defaults
	})
	require.NoError(t, err)
	assert.Equal(t, defaultEmailAttr, p.emailAttr)
	assert.Equal(t, defaultNameAttr, p.nameAttr)
	assert.Equal(t, defaultGroupsAttr, p.groupsAttr)
}

// TestNewProvider_ExplicitAttributes validates that explicit attribute names
// are used as-is.
func TestNewProvider_ExplicitAttributes(t *testing.T) {
	p, err := NewProvider(Config{
		Name:           "corp2",
		IDPMetadataXML: idpMetadata(t),
		SPEntityID:     "https://sp.example/metadata2",
		ACSURL:         "https://sp.example/acs2",
		EmailAttr:      "mail",
		NameAttr:       "cn",
		GroupsAttr:     "memberOf",
	})
	require.NoError(t, err)
	assert.Equal(t, "mail", p.emailAttr)
	assert.Equal(t, "cn", p.nameAttr)
	assert.Equal(t, "memberOf", p.groupsAttr)
}

// TestProvider_Name validates that the name accessor returns the configured name.
func TestProvider_Name(t *testing.T) {
	p := testProvider(t)
	assert.Equal(t, "corp", p.Name())
}

// TestNewProvider_BlankACSURL validates that a blank ACSURL is rejected.
func TestNewProvider_BlankACSURL(t *testing.T) {
	_, err := NewProvider(Config{
		IDPMetadataXML: idpMetadata(t),
		SPEntityID:     "https://x",
		ACSURL:         "   ",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "acs_url")
}

// TestNewProvider_BlankSPEntityID validates that a blank SPEntityID is rejected.
func TestNewProvider_BlankSPEntityID(t *testing.T) {
	_, err := NewProvider(Config{
		IDPMetadataXML: idpMetadata(t),
		SPEntityID:     "   ",
		ACSURL:         "https://x/acs",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sp_entity_id")
}

// TestRequireAudienceRestriction_NilAssertion validates nil assertion is
// rejected without panic.
func TestRequireAudienceRestriction_NilAssertion(t *testing.T) {
	fn := requireAudienceRestriction("https://sp.example")
	err := fn(nil)
	require.Error(t, err)
}

// idpMetadataPostOnly builds IdP metadata with only an HTTP-POST SSO binding
// (no HTTP-Redirect binding), so GetSSOBindingLocation(HTTPRedirectBinding)
// returns "". Used to cover the "no redirect binding" branch in AuthnRequest.
func idpMetadataPostOnly(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-idp-post-only"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert := base64.StdEncoding.EncodeToString(der)

	return []byte(fmt.Sprintf(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.post.example/entity">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>%s</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.post.example/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, cert))
}

// TestAuthnRequest_NoRedirectBinding covers the early-return error path in
// AuthnRequest when the IdP advertises no HTTP-Redirect SSO binding.
func TestAuthnRequest_NoRedirectBinding(t *testing.T) {
	p, err := NewProvider(Config{
		Name:           "post-only-idp",
		IDPMetadataXML: idpMetadataPostOnly(t),
		SPEntityID:     "https://sp.example/metadata",
		ACSURL:         "https://sp.example/acs",
	})
	require.NoError(t, err)

	_, _, err = p.AuthnRequest("state")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP-Redirect")
}

// TestParseResponse_NonInvalidResponseError covers the else-branch in
// ParseResponse where the library returns an error that is NOT an
// *InvalidResponseError (e.g. a plain parse error from a nil body).
func TestParseResponse_NonInvalidResponseError(t *testing.T) {
	p := testProvider(t)
	// A request with an empty SAMLResponse field causes the library to return a
	// plain error (not *InvalidResponseError). We still get errInvalidSAMLResponse.
	req := httptest.NewRequest(http.MethodPost, "https://keyorix.internal/auth/saml/corp/acs",
		strings.NewReader("SAMLResponse="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := p.ParseResponse(req, nil)
	require.Error(t, err)
	assert.Same(t, errInvalidSAMLResponse, err)
}

// TestParseIDPMetadata_EntitiesDescriptorNoIDP covers the branch where the
// metadata is a valid EntitiesDescriptor but none of the contained
// EntityDescriptors carries an IDPSSODescriptor.
func TestParseIDPMetadata_EntitiesDescriptorNoIDP(t *testing.T) {
	// EntitiesDescriptor wrapping a single SP-only entity — no IDP role.
	xml := []byte(`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" Name="test">
  <EntityDescriptor entityID="https://sp.example">
    <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"></SPSSODescriptor>
  </EntityDescriptor>
</EntitiesDescriptor>`)
	_, err := parseIDPMetadata(xml)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "IDPSSODescriptor")
}

// TestParseIDPMetadata_EntitiesDescriptorWithIDP covers the happy path in the
// EntitiesDescriptor branch: at least one entity carries an IDPSSODescriptor.
func TestParseIDPMetadata_EntitiesDescriptorWithIDP(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-idp-multi"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert := base64.StdEncoding.EncodeToString(der)

	xml := []byte(fmt.Sprintf(`<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" Name="test">
  <EntityDescriptor entityID="https://sp.example">
    <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"></SPSSODescriptor>
  </EntityDescriptor>
  <EntityDescriptor entityID="https://idp.multi.example/entity">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <KeyDescriptor use="signing">
        <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
          <X509Data><X509Certificate>%s</X509Certificate></X509Data>
        </KeyInfo>
      </KeyDescriptor>
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.multi.example/sso"/>
    </IDPSSODescriptor>
  </EntityDescriptor>
</EntitiesDescriptor>`, cert))

	entity, err := parseIDPMetadata(xml)
	require.NoError(t, err)
	require.NotNil(t, entity)
	assert.Equal(t, "https://idp.multi.example/entity", entity.EntityID)
	assert.NotEmpty(t, entity.IDPSSODescriptors)
}

// TestParseIDPMetadata_InvalidXMLNotEntitiesDescriptor covers the branch in
// parseIDPMetadata where xml.Unmarshal fails with an error that does NOT
// mention "EntitiesDescriptor" (e.g. truly malformed XML).
func TestParseIDPMetadata_InvalidXMLNotEntitiesDescriptor(t *testing.T) {
	// Malformed XML that passes the round-trip validator but fails Unmarshal into
	// EntityDescriptor with a non-"EntitiesDescriptor" error is tricky; the
	// easiest trigger is XML that is syntactically valid but semantically wrong
	// such that the Unmarshal produces an error whose message doesn't mention
	// "EntitiesDescriptor". An unclosed element triggers a parse error.
	// However the round-trip validator will also reject truly malformed XML.
	// Instead, provide XML whose root element is something completely unexpected
	// but syntactically valid — Unmarshal into EntityDescriptor will return nil
	// (Go's xml decoder ignores unknown elements), so let's use an element that
	// causes a type mismatch on an attribute value.
	//
	// The simplest reliable trigger: a root element that IS "EntityDescriptor"
	// but contains an attribute that Go's xml decoder can't parse into the Go
	// struct (e.g. a required integer field with a non-integer value). In
	// practice the crewjam structs use string fields so this is hard to break.
	//
	// After careful inspection the only reachable path for `err != nil &&
	// !Contains("EntitiesDescriptor")` is when xml.Unmarshal returns an error
	// whose text doesn't contain "EntitiesDescriptor". The crewjam EntityDescriptor
	// struct uses loose string fields, so Unmarshal never returns an error for
	// unknown/wrong content — it just ignores them. This branch is therefore
	// unreachable in normal operation (the round-trip validator catches
	// syntactically-invalid XML first). We document that finding rather than
	// write a test that can never compile/run.
	t.Skip("the non-EntitiesDescriptor xml.Unmarshal error path is structurally unreachable: " +
		"xrv.Validate rejects malformed XML before Unmarshal, and crewjam's EntityDescriptor " +
		"accepts any well-formed XML silently (loose string fields)")
}

// TestNewProvider_InvalidACSURL covers the url.Parse error path for ACSURL.
// Go's url.Parse is extremely permissive and only returns an error on control
// characters. We use a URL containing a raw ASCII control character (0x7f DEL).
func TestNewProvider_InvalidACSURL(t *testing.T) {
	md := idpMetadata(t)
	_, err := NewProvider(Config{
		IDPMetadataXML: md,
		SPEntityID:     "https://sp.example/metadata",
		// Raw DEL control character makes url.Parse return an error.
		ACSURL: "https://sp.example/acs\x7f",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid acs_url")
}

// TestNewProvider_InvalidSPEntityID covers the url.Parse error path for SPEntityID.
func TestNewProvider_InvalidSPEntityID(t *testing.T) {
	md := idpMetadata(t)
	_, err := NewProvider(Config{
		IDPMetadataXML: md,
		// Raw DEL control character makes url.Parse return an error.
		SPEntityID: "https://sp.example/meta\x7f",
		ACSURL:     "https://sp.example/acs",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid sp_entity_id")
}

// TestExtractAssertion_AllBlankValues covers the `continue` branch inside
// extractAssertion: when all values of an attribute are blank/whitespace,
// attributeValues returns an empty slice and the attribute is skipped.
func TestExtractAssertion_AllBlankValues(t *testing.T) {
	a := &csaml.Assertion{
		AttributeStatements: []csaml.AttributeStatement{{
			Attributes: []csaml.Attribute{
				// All values are blank — attributeValues returns [] → continue branch.
				{
					Name: defaultEmailAttr,
					Values: []csaml.AttributeValue{
						{Value: ""},
						{Value: "   "},
						{Value: "\t"},
					},
				},
				// A real email on a subsequent attribute to confirm other attrs still work.
				{
					Name:   defaultNameAttr,
					Values: []csaml.AttributeValue{{Value: "Alice"}},
				},
			},
		}},
	}
	info := extractAssertion(a, defaultEmailAttr, defaultNameAttr, defaultGroupsAttr)
	assert.Empty(t, info.Email, "attribute with all-blank values must be skipped")
	assert.Equal(t, "Alice", info.Name)
}

package saml

import (
	"testing"

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

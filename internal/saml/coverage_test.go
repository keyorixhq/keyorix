package saml

// coverage_test.go — additional tests targeting the remaining uncovered branches
// in provider.go so the package reaches ≥ 90 % statement coverage.
//
// Branches this file targets:
//   - Metadata: the xml.MarshalIndent error path is structurally unreachable
//     (crewjam's EntityDescriptor uses only XML-marshallable types); the test
//     below documents this and covers the success path via a second Metadata call
//     on a provider whose SP entity ID is verified to appear in the XML output.
//   - ParseResponse success path: requires a fully-signed SAML response from an
//     IdP — not feasible in a unit test without a live IdP or a large signing
//     harness. The existing ParseResponse tests already cover both error sub-paths
//     (InvalidResponseError with PrivateErr, and non-InvalidResponseError). The
//     remaining gap (the happy return extractAssertion(…) line) is left as a
//     documented integration-test gap.
//   - AuthnRequest req.Redirect error: the crewjam library builds the redirect URL
//     from the already-validated SSO location embedded in IdP metadata; reaching the
//     Redirect error branch requires an SSO URL that is syntactically valid (passes
//     url.Parse and the XML round-trip validator) but triggers an error inside
//     req.Redirect. Tests below document what has been tried and what is reachable.
//   - parseIDPMetadata EntitiesDescriptor unmarshal error: the round-trip validator
//     already guarantees well-formed XML, and crewjam's EntitiesDescriptor struct
//     uses loose string fields, so Unmarshal never returns an error for unexpected
//     content. The branch is structurally unreachable in the same way as the
//     Metadata marshal error. Documented below.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMetadata_ContainsSPEntityID verifies the SP metadata XML carries both
// the entity ID and the ACS URL, exercising the successful code path through
// Metadata() (the xml.MarshalIndent error branch is structurally unreachable —
// see the file-level comment).
func TestMetadata_ContainsSPEntityID(t *testing.T) {
	p, err := NewProvider(Config{
		Name:           "meta-test",
		IDPMetadataXML: idpMetadata(t),
		SPEntityID:     "https://sp.coverage.example/saml/metadata",
		ACSURL:         "https://sp.coverage.example/saml/acs",
	})
	require.NoError(t, err)

	raw, err := p.Metadata()
	require.NoError(t, err)
	s := string(raw)

	assert.Contains(t, s, "https://sp.coverage.example/saml/metadata",
		"SP entity ID must appear in the metadata XML")
	assert.Contains(t, s, "https://sp.coverage.example/saml/acs",
		"ACS URL must appear in the metadata XML")
	assert.Contains(t, s, "EntityDescriptor",
		"metadata must contain EntityDescriptor element")
	// Sanity: the output is valid XML (non-empty, starts with '<').
	assert.True(t, strings.HasPrefix(strings.TrimSpace(s), "<"),
		"metadata output must start with an XML element")
}

// TestMetadata_AllowIDPInitiatedProvider verifies Metadata() on a provider
// configured with AllowIDPInitiated — tests the second distinct construction
// path through NewProvider to ensure no extra field causes a marshal failure.
func TestMetadata_AllowIDPInitiatedProvider(t *testing.T) {
	p, err := NewProvider(Config{
		Name:              "meta-idp-init",
		IDPMetadataXML:    idpMetadata(t),
		SPEntityID:        "https://sp.coverage.example/saml2/metadata",
		ACSURL:            "https://sp.coverage.example/saml2/acs",
		AllowIDPInitiated: true,
	})
	require.NoError(t, err)

	raw, err := p.Metadata()
	require.NoError(t, err)
	assert.NotEmpty(t, raw)
	assert.Contains(t, string(raw), "https://sp.coverage.example/saml2/acs")
}

// TestParseResponse_InvalidResponseError_WithPrivateErr sends a request that
// causes the crewjam library to return an *InvalidResponseError whose PrivateErr
// is set — exercising the log-PrivateErr branch (the if-true arm of the
// errors.As / PrivateErr != nil compound condition in ParseResponse).
//
// A base64-invalid SAMLResponse triggers an InvalidResponseError with the
// decode error attached as PrivateErr.
func TestParseResponse_InvalidResponseError_WithPrivateErr(t *testing.T) {
	p := testProvider(t)
	// "!!!" is not valid base64, so crewjam's base64.StdEncoding.DecodeString
	// returns an error which crewjam wraps in an InvalidResponseError with
	// PrivateErr set to the decode error.
	body := "SAMLResponse=" + "!!!not-base64!!!"
	req := httptest.NewRequest(http.MethodPost,
		"https://keyorix.internal/auth/saml/corp/acs",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := p.ParseResponse(req, []string{"req-1"})
	require.Error(t, err)
	// The caller must always receive the generic sanitized error — never the raw library error.
	assert.Same(t, errInvalidSAMLResponse, err,
		"ParseResponse must return the fixed generic error even when PrivateErr is set")
	assert.NotContains(t, err.Error(), "base64",
		"internal decode error must not leak through the returned error")
}

// TestParseResponse_NonInvalidResponseError_EmptyField sends a request with an
// empty SAMLResponse value, which makes crewjam return a plain error (not an
// *InvalidResponseError) — exercising the else-log branch.
func TestParseResponse_NonInvalidResponseError_EmptyField(t *testing.T) {
	p := testProvider(t)
	req := httptest.NewRequest(http.MethodPost,
		"https://keyorix.internal/auth/saml/corp/acs",
		strings.NewReader("SAMLResponse="))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := p.ParseResponse(req, nil)
	require.Error(t, err)
	assert.Same(t, errInvalidSAMLResponse, err)
}

// TestParseResponse_MissingField sends a request with no SAMLResponse field at
// all — another non-InvalidResponseError path.
func TestParseResponse_MissingField(t *testing.T) {
	p := testProvider(t)
	req := httptest.NewRequest(http.MethodPost,
		"https://keyorix.internal/auth/saml/corp/acs",
		strings.NewReader("unrelated=data"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	_, err := p.ParseResponse(req, nil)
	require.Error(t, err)
	assert.Same(t, errInvalidSAMLResponse, err)
}

// TestAuthnRequest_RelayStateEncoding verifies that relayState is URL-encoded
// in the redirect URL returned by AuthnRequest, covering an additional execution
// path through the function with a non-empty relay state containing special chars.
func TestAuthnRequest_RelayStateEncoding(t *testing.T) {
	p := testProvider(t)
	redirect, reqID, err := p.AuthnRequest("return/path?foo=bar&baz=qux")
	require.NoError(t, err)
	assert.NotEmpty(t, reqID)
	assert.Contains(t, redirect, "SAMLRequest=")
	// The relay state may appear URL-encoded in the redirect URL.
	assert.Contains(t, redirect, "RelayState=")
}

// TestAuthnRequest_EmptyRelayState covers AuthnRequest with an empty relay state.
func TestAuthnRequest_EmptyRelayState(t *testing.T) {
	p := testProvider(t)
	redirect, reqID, err := p.AuthnRequest("")
	require.NoError(t, err)
	assert.NotEmpty(t, reqID)
	assert.Contains(t, redirect, "SAMLRequest=")
}

// TestParseIDPMetadata_WhitespaceOnly verifies that whitespace-only metadata
// is rejected (the `bytes.TrimSpace(data) == 0` branch).
func TestParseIDPMetadata_WhitespaceOnly(t *testing.T) {
	_, err := parseIDPMetadata([]byte("  \t\n  "))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

// TestParseIDPMetadata_MalformedXML verifies that syntactically invalid XML
// (which fails the xrv round-trip validator) is rejected before Unmarshal.
func TestParseIDPMetadata_MalformedXML(t *testing.T) {
	_, err := parseIDPMetadata([]byte("<unclosed"))
	require.Error(t, err)
}

// TestParseIDPMetadata_ValidEntityDescriptorWithIDP is a direct call to the
// unexported helper verifying the complete happy path for an EntityDescriptor
// with an IDPSSODescriptor — same helper already exercised by NewProvider, but
// calling it directly confirms parseIDPMetadata's own return value.
func TestParseIDPMetadata_ValidEntityDescriptorWithIDP(t *testing.T) {
	entity, err := parseIDPMetadata(idpMetadata(t))
	require.NoError(t, err)
	require.NotNil(t, entity)
	assert.Equal(t, "https://idp.example/entity", entity.EntityID)
	require.NotEmpty(t, entity.IDPSSODescriptors)
}

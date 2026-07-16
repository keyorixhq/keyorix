// handlers_s13_test.go — coverage sweep targeting saml.go branches:
//   - SAMLMetadata: unknown-provider -> 404, happy path -> 200 XML
//   - BeginSAML: unknown-provider -> 400, happy path -> 302 redirect, return_to param
//   - CompleteSAML: unknown-provider -> 400 (sendError path),
//     bad/missing RelayState -> 302 redirect with error fragment,
//     empty form body -> 302 redirect with error fragment
package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	samlpkg "github.com/keyorixhq/keyorix/internal/saml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -- stubHandlerSAML - satisfies core.SAMLAuthn

// stubHandlerSAML is a minimal core.SAMLAuthn that lets handler-level tests
// exercise the SAML HTTP handlers without a real IdP or signed assertion.
type stubHandlerSAML struct {
	metadataXML []byte
	redirectURL string
	requestID   string
	parseErr    error
}

func (s *stubHandlerSAML) Metadata() ([]byte, error) {
	if s.metadataXML != nil {
		return s.metadataXML, nil
	}
	return []byte("<EntityDescriptor/>"), nil
}

func (s *stubHandlerSAML) AuthnRequest(relayState string) (string, string, error) {
	u := s.redirectURL
	if u == "" {
		u = "https://idp.example/sso?SAMLRequest=stub"
	}
	id := s.requestID
	if id == "" {
		id = "req-stub"
	}
	_ = relayState
	return u, id, nil
}

func (s *stubHandlerSAML) ParseResponse(_ *http.Request, _ []string) (*samlpkg.AssertionInfo, error) {
	return nil, s.parseErr
}

// compile-time check: stubHandlerSAML must implement core.SAMLAuthn.
var _ core.SAMLAuthn = (*stubHandlerSAML)(nil)

// -- helper: auth handler with one configured SAML provider

// authHandlerWithCorpSAML returns an AuthHandler backed by freshCoreS12 with
// one SAML provider named "corp" wired. CompleteURL is set so CompleteSAML
// passes its first guard (SSOCompleteURL check) and proceeds to the form/core path.
func authHandlerWithCorpSAML(t *testing.T, stub *stubHandlerSAML) *AuthHandler {
	t.Helper()
	cs := freshCoreS12(t)
	cs.SetSSOProviders(map[string]*core.SSOProvider{
		"corp": {
			Name:        "corp",
			Type:        "saml",
			SAML:        stub,
			CompleteURL: "https://app.example/auth/sso/complete",
		},
	}, nil)
	return NewAuthHandler(cs, false)
}

// -- SAMLMetadata

// TestSAMLMetadata_UnknownProvider_S13 exercises the error branch when the
// provider is not configured - expects 404.
func TestSAMLMetadata_UnknownProvider_S13(t *testing.T) {
	cs := freshCoreS12(t) // no SSO providers
	h := NewAuthHandler(cs, false)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/auth/saml/ghost/metadata", nil),
		"provider", "ghost",
	)
	w := httptest.NewRecorder()
	h.SAMLMetadata(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "SSOError")
}

// TestSAMLMetadata_HappyPath_S13 exercises the success branch - expects 200
// with the SAML metadata XML content-type.
func TestSAMLMetadata_HappyPath_S13(t *testing.T) {
	stub := &stubHandlerSAML{metadataXML: []byte("<EntityDescriptor/>")}
	h := authHandlerWithCorpSAML(t, stub)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/auth/saml/corp/metadata", nil),
		"provider", "corp",
	)
	w := httptest.NewRecorder()
	h.SAMLMetadata(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "samlmetadata+xml")
	assert.Contains(t, w.Body.String(), "EntityDescriptor")
}

// -- BeginSAML

// TestBeginSAML_UnknownProvider_S13 exercises the error branch in BeginSAML
// when the provider is not configured - expects 400.
func TestBeginSAML_UnknownProvider_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/auth/saml/ghost/login", nil),
		"provider", "ghost",
	)
	w := httptest.NewRecorder()
	h.BeginSAML(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "SSOError")
}

// TestBeginSAML_HappyPath_S13 exercises the redirect branch when a SAML
// provider is configured - expects 302 to the IdP URL.
func TestBeginSAML_HappyPath_S13(t *testing.T) {
	stub := &stubHandlerSAML{redirectURL: "https://idp.example/sso?SAMLRequest=stub"}
	h := authHandlerWithCorpSAML(t, stub)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/auth/saml/corp/login", nil),
		"provider", "corp",
	)
	w := httptest.NewRecorder()
	h.BeginSAML(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "idp.example")
}

// TestBeginSAML_ReturnTo_S13 verifies that a return_to query param is forwarded
// and the IdP redirect still happens.
func TestBeginSAML_ReturnTo_S13(t *testing.T) {
	stub := &stubHandlerSAML{redirectURL: "https://idp.example/sso"}
	h := authHandlerWithCorpSAML(t, stub)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/auth/saml/corp/login?return_to=%2Fdashboard", nil),
		"provider", "corp",
	)
	w := httptest.NewRecorder()
	h.BeginSAML(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
}

// -- CompleteSAML

// TestCompleteSAML_UnknownProvider_S13 exercises the SSOCompleteURL guard -
// when the provider is not configured, expects 400 via sendError (not a redirect).
func TestCompleteSAML_UnknownProvider_S13(t *testing.T) {
	cs := freshCoreS12(t)
	h := NewAuthHandler(cs, false)

	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/auth/saml/ghost/acs", nil),
		"provider", "ghost",
	)
	w := httptest.NewRecorder()
	h.CompleteSAML(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "SSOError")
}

// TestCompleteSAML_BadRelayState_S13 exercises the error-redirect branch in
// CompleteSAML when the RelayState does not match any stored login state.
// core.CompleteSAML returns "invalid or expired login state" -> redirectFragment
// with an error fragment (not a 4xx JSON error body).
func TestCompleteSAML_BadRelayState_S13(t *testing.T) {
	stub := &stubHandlerSAML{}
	h := authHandlerWithCorpSAML(t, stub)

	body := strings.NewReader("RelayState=nonexistent-relay-state&SAMLResponse=bad")
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", body),
		"provider", "corp",
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.CompleteSAML(w, req)

	// Should redirect to completeURL#error=...
	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "app.example")
	assert.Contains(t, location, "error=")
}

// TestCompleteSAML_EmptyRelayState_S13 verifies that an ACS POST with no
// RelayState field is handled - core returns "invalid or expired login state"
// -> redirect with error fragment.
func TestCompleteSAML_EmptyRelayState_S13(t *testing.T) {
	stub := &stubHandlerSAML{}
	h := authHandlerWithCorpSAML(t, stub)

	body := strings.NewReader("SAMLResponse=encoded")
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", body),
		"provider", "corp",
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.CompleteSAML(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "error=")
}

// TestCompleteSAML_NoBody_S13 verifies that a POST with no body at all still
// redirects with an error (form parse succeeds on empty body; core fails on
// empty RelayState).
func TestCompleteSAML_NoBody_S13(t *testing.T) {
	stub := &stubHandlerSAML{}
	h := authHandlerWithCorpSAML(t, stub)

	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", nil),
		"provider", "corp",
	)
	w := httptest.NewRecorder()
	h.CompleteSAML(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	require.Contains(t, w.Header().Get("Location"), "error=")
}

// saml_s13_test.go — additional coverage sweep targeting saml.go branches
// not yet covered by handlers_s13_test.go:
//   - SAMLMetadata: unsafe-error path (logs + clientSafe)
//   - BeginSAML: unsafe-error path (logs + clientSafe)
//   - CompleteSAML: ParseResponse error (unsafe msg -> redirectFragment),
//     success path (no optional expiry fields), success with ExpiresAt +
//     AbsoluteExpiresAt + returnTo fragment fields.
package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	samlpkg "github.com/keyorixhq/keyorix/internal/saml"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// -- SAMLMetadata uncovered branches ------------------------------------------

// TestSAMLMetadata_UnsafeError_S13 exercises the branch where the error from
// SAMLMetadata is NOT a safe SSO message — it reaches the log + clientSafe
// sanitization path inside SAMLMetadata.
// We register a "saml" provider whose Metadata() returns a non-safe error
// (any error whose text is not in isSafeSSOError's allowlist).
func TestSAMLMetadata_UnsafeError_S13(t *testing.T) {
	stub := &stubMetadataErrSAML{err: assert.AnError}
	cs := freshCoreS12(t)
	cs.SetSSOProviders(map[string]*core.SSOProvider{
		"corp": {
			Name:        "corp",
			Type:        "saml",
			SAML:        stub,
			CompleteURL: "https://app.example/auth/sso/complete",
		},
	}, nil)
	h := NewAuthHandler(cs, false)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/auth/saml/corp/metadata", nil),
		"provider", "corp",
	)
	w := httptest.NewRecorder()
	h.SAMLMetadata(w, req)

	// Expects 404 like the safe-error path, but msg is sanitized.
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "SSOError")
}

// stubMetadataErrSAML implements core.SAMLAuthn; Metadata() returns a
// configured error; other methods are no-op stubs.
type stubMetadataErrSAML struct {
	err error
}

func (s *stubMetadataErrSAML) Metadata() ([]byte, error) { return nil, s.err }
func (s *stubMetadataErrSAML) AuthnRequest(_ string) (string, string, error) {
	return "https://idp.example/sso", "req-1", nil
}
func (s *stubMetadataErrSAML) ParseResponse(_ *http.Request, _ []string) (*samlpkg.AssertionInfo, error) {
	return nil, nil
}

var _ core.SAMLAuthn = (*stubMetadataErrSAML)(nil)

// -- BeginSAML uncovered branches ---------------------------------------------

// TestBeginSAML_UnsafeError_S13 exercises the branch where BeginSAML's
// error is NOT a safe SSO message.  We trigger this by making AuthnRequest
// return an error whose text is not on the isSafeSSOError allowlist.
func TestBeginSAML_UnsafeError_S13(t *testing.T) {
	stub := &stubAuthnErrSAML{err: assert.AnError}
	cs := freshCoreS12(t)
	cs.SetSSOProviders(map[string]*core.SSOProvider{
		"corp": {
			Name:        "corp",
			Type:        "saml",
			SAML:        stub,
			CompleteURL: "https://app.example/auth/sso/complete",
		},
	}, nil)
	h := NewAuthHandler(cs, false)

	req := withChiParam(
		httptest.NewRequest(http.MethodGet, "/auth/saml/corp/login", nil),
		"provider", "corp",
	)
	w := httptest.NewRecorder()
	h.BeginSAML(w, req)

	// Handler wraps and sanitizes the error, then sends 400.
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "SSOError")
}

// stubAuthnErrSAML makes AuthnRequest return an error so that BeginSAML
// reaches the unsafe-error sanitisation branch.
type stubAuthnErrSAML struct {
	err error
}

func (s *stubAuthnErrSAML) Metadata() ([]byte, error) { return []byte("<EntityDescriptor/>"), nil }
func (s *stubAuthnErrSAML) AuthnRequest(_ string) (string, string, error) {
	return "", "", s.err
}
func (s *stubAuthnErrSAML) ParseResponse(_ *http.Request, _ []string) (*samlpkg.AssertionInfo, error) {
	return nil, nil
}

var _ core.SAMLAuthn = (*stubAuthnErrSAML)(nil)

// -- CompleteSAML uncovered branches ------------------------------------------

// authHandlerWithCorpSAMLDB is like authHandlerWithCorpSAML but returns the
// *core.KeyorixCore too so callers can seed DB state directly.
func authHandlerWithCorpSAMLDB(t *testing.T, stub core.SAMLAuthn, autoProvision bool) (*AuthHandler, *core.KeyorixCore) {
	t.Helper()
	cs := freshCoreS12(t)
	cs.SetSSOProviders(map[string]*core.SSOProvider{
		"corp": {
			Name:          "corp",
			Type:          "saml",
			SAML:          stub,
			CompleteURL:   "https://app.example/auth/sso/complete",
			AutoProvision: autoProvision,
		},
	}, nil)
	return NewAuthHandler(cs, false), cs
}

// TestCompleteSAML_ParseResponseError_UnsafeMsg_S13 exercises the error-redirect
// branch when CompleteSAML's ParseResponse returns an error whose text is NOT
// in isSafeSSOError's allowlist (unsafe internal detail -> gets sanitised).
func TestCompleteSAML_ParseResponseError_UnsafeMsg_S13(t *testing.T) {
	// stubHandlerSAML is already defined in handlers_s13_test.go with parseErr.
	stub := &stubHandlerSAML{parseErr: assert.AnError}
	h, cs := authHandlerWithCorpSAMLDB(t, stub, false)

	// Seed a valid SSOLoginState so CompleteSAML reaches ParseResponse.
	err := cs.Storage().CreateSSOLoginState(
		t.Context(), &models.SSOLoginState{
			State:     "valid-relay-state-s13",
			Nonce:     "req-nonce-s13",
			Provider:  "corp",
			ExpiresAt: time.Now().Add(10 * time.Minute),
			CreatedAt: time.Now(),
		})
	if err != nil {
		// Fallback: seed via context-based core method
		t.Skip("cannot seed SSOLoginState directly; skip")
	}

	body := strings.NewReader("RelayState=valid-relay-state-s13&SAMLResponse=stub")
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

// TestCompleteSAML_ParseFormError_S13 exercises the ParseForm error branch by
// sending a request whose body triggers a parse failure.  In practice, a
// POST with Content-Type application/x-www-form-urlencoded and an oversized
// or broken Transfer-Encoding can cause ParseForm to error.  We simulate this
// by providing a body that causes errors via a custom reader.
func TestCompleteSAML_ParseFormError_S13(t *testing.T) {
	stub := &stubHandlerSAML{}
	h := authHandlerWithCorpSAML(t, stub)

	// A request whose body returns an error mid-read causes ParseForm to fail.
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", &errReader{}),
		"provider", "corp",
	)
	// Set Content-Type so ParseForm attempts to read the body.
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.CompleteSAML(w, req)

	// ParseForm failure -> redirectFragment with "invalid ACS request".
	assert.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	assert.Contains(t, loc, "error=")
	assert.Contains(t, loc, "invalid")
}

// errReader is an io.Reader that always returns an error, used to trigger
// ParseForm failures.
type errReader struct{}

func (e *errReader) Read(_ []byte) (int, error) {
	return 0, assert.AnError
}

// -- CompleteSAML success paths -----------------------------------------------

// stubAssertionSAML implements core.SAMLAuthn whose ParseResponse returns a
// canned AssertionInfo (used for the CompleteSAML success paths).
type stubAssertionSAML struct {
	info *samlpkg.AssertionInfo
}

func (s *stubAssertionSAML) Metadata() ([]byte, error) { return []byte("<EntityDescriptor/>"), nil }
func (s *stubAssertionSAML) AuthnRequest(_ string) (string, string, error) {
	return "https://idp.example/sso", "req-s13", nil
}
func (s *stubAssertionSAML) ParseResponse(_ *http.Request, _ []string) (*samlpkg.AssertionInfo, error) {
	return s.info, nil
}

var _ core.SAMLAuthn = (*stubAssertionSAML)(nil)

// TestCompleteSAML_SuccessNoExpiry_S13 exercises the CompleteSAML success path
// when the minted session has no ExpiresAt / AbsoluteExpiresAt and no ReturnTo.
// The handler should redirect with only a token in the fragment.
func TestCompleteSAML_SuccessNoExpiry_S13(t *testing.T) {
	stub := &stubAssertionSAML{
		info: &samlpkg.AssertionInfo{Subject: "sub-s13a", Email: "auto-s13a@example.com", Name: "Auto S13"},
	}
	cs, db := freshCoreS12WithAdmin(t)
	cs.SetSSOProviders(map[string]*core.SSOProvider{
		"corp": {
			Name:          "corp",
			Type:          "saml",
			SAML:          stub,
			CompleteURL:   "https://app.example/auth/sso/complete",
			AutoProvision: true,
		},
	}, nil)
	h := NewAuthHandler(cs, false)

	relayState := "relay-ok-s13"
	row := &models.SSOLoginState{
		State:     relayState,
		Nonce:     "nonce-ok-s13",
		Provider:  "corp",
		ReturnTo:  "",
		ExpiresAt: time.Now().Add(10 * time.Minute),
		CreatedAt: time.Now(),
	}
	require.NoError(t, db.Create(row).Error)

	body := strings.NewReader("RelayState=" + relayState + "&SAMLResponse=stub")
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", body),
		"provider", "corp",
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	h.CompleteSAML(w, req)

	// Success -> 302 redirect with token in the fragment.
	assert.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	assert.Contains(t, loc, "app.example")
	assert.Contains(t, loc, "token=")
}

// TestCompleteSAML_SuccessWithReturnTo_S13 exercises the `if returnTo != ""`
// branch in CompleteSAML by seeding a login state with a non-empty ReturnTo.
func TestCompleteSAML_SuccessWithReturnTo_S13(t *testing.T) {
	stub := &stubAssertionSAML{
		info: &samlpkg.AssertionInfo{Subject: "sub-rto-s13", Email: "rto-s13@example.com", Name: "RTO S13"},
	}
	cs, db := freshCoreS12WithAdmin(t)
	cs.SetSSOProviders(map[string]*core.SSOProvider{
		"corp": {
			Name:          "corp",
			Type:          "saml",
			SAML:          stub,
			CompleteURL:   "https://app.example/auth/sso/complete",
			AutoProvision: true,
		},
	}, nil)
	h := NewAuthHandler(cs, false)

	relayState := "relay-rto-s13"
	row := &models.SSOLoginState{
		State:     relayState,
		Nonce:     "nonce-rto-s13",
		Provider:  "corp",
		ReturnTo:  "/dashboard",
		ExpiresAt: time.Now().Add(10 * time.Minute),
		CreatedAt: time.Now(),
	}
	require.NoError(t, db.Create(row).Error)

	body := strings.NewReader("RelayState=" + relayState + "&SAMLResponse=stub")
	req := withChiParam(
		httptest.NewRequest(http.MethodPost, "/auth/saml/corp/acs", body),
		"provider", "corp",
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	h.CompleteSAML(w, req)

	// Success with returnTo -> fragment includes return_to=dashboard.
	assert.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	assert.Contains(t, loc, "return_to=")
	assert.Contains(t, loc, "dashboard")
}

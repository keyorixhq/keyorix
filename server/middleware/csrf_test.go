package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nextOK is a trivial handler that records it was called.
func nextOK(called *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if called != nil {
			*called = true
		}
		w.WriteHeader(http.StatusOK)
	})
}

// TestRequireCSRF_SafeMethodsPassThrough verifies GET/HEAD/OPTIONS bypass CSRF checks.
func TestRequireCSRF_SafeMethodsPassThrough(t *testing.T) {
	called := false
	h := RequireCSRF(nextOK(&called))
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		called = false
		req := httptest.NewRequest(method, "/api/v1/secrets", nil)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "sess"})
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code, "safe method %s must pass through CSRF check", method)
		assert.True(t, called)
	}
}

// TestRequireCSRF_BearerOnlyRequestPassesThrough verifies that POST without a session cookie is exempt.
func TestRequireCSRF_BearerOnlyRequestPassesThrough(t *testing.T) {
	called := false
	h := RequireCSRF(nextOK(&called))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", nil)
	// No session cookie — Bearer-only caller
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code, "a request without a session cookie is Bearer-only and must not be CSRF-checked")
	assert.True(t, called)
}

// TestRequireCSRF_MissingCSRFCookieForbidden verifies that a cookie-authenticated POST
// without a CSRF cookie is rejected.
func TestRequireCSRF_MissingCSRFCookieForbidden(t *testing.T) {
	called := false
	h := RequireCSRF(nextOK(&called))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "my-session"})
	// No CSRF cookie
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.False(t, called)
}

// TestRequireCSRF_MissingCSRFHeaderForbidden verifies rejection when the CSRF cookie is
// present but the echo header is missing.
func TestRequireCSRF_MissingCSRFHeaderForbidden(t *testing.T) {
	called := false
	h := RequireCSRF(nextOK(&called))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "my-session"})
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "csrf-value"})
	// X-CSRF-Token header intentionally absent
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.False(t, called)
}

// TestRequireCSRF_MismatchedTokenForbidden verifies that a header value that doesn't match
// the cookie value is rejected.
func TestRequireCSRF_MismatchedTokenForbidden(t *testing.T) {
	called := false
	h := RequireCSRF(nextOK(&called))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "my-session"})
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "csrf-value"})
	req.Header.Set(CSRFHeaderName, "wrong-value")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.False(t, called)
}

// TestRequireCSRF_MatchingTokenAllowed verifies that the double-submit pattern allows
// the request through when the cookie and header match.
func TestRequireCSRF_MatchingTokenAllowed(t *testing.T) {
	called := false
	h := RequireCSRF(nextOK(&called))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "my-session"})
	req.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "csrf-value"})
	req.Header.Set(CSRFHeaderName, "csrf-value")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, called)
}

// TestRequireCSRF_PUTAndDELETEAreCovered ensures all state-changing methods are gated.
func TestRequireCSRF_PUTAndDELETEAreCovered(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			called := false
			h := RequireCSRF(nextOK(&called))
			req := httptest.NewRequest(method, "/api/v1/secrets/1", nil)
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "my-session"})
			// No CSRF cookie → must be rejected
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusForbidden, rr.Code, "method %s must require CSRF token", method)
			assert.False(t, called)
		})
	}
}

// TestGenerateCSRFToken verifies that the token is non-empty and random across calls.
func TestGenerateCSRFToken(t *testing.T) {
	tok1, err := GenerateCSRFToken()
	require.NoError(t, err)
	require.NotEmpty(t, tok1)

	tok2, err := GenerateCSRFToken()
	require.NoError(t, err)
	assert.NotEqual(t, tok1, tok2, "consecutive CSRF tokens must be distinct")
	// A 32-byte hex is 64 characters long.
	assert.Len(t, tok1, 64)
}

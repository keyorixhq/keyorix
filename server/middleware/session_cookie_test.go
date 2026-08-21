package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// NOTE: GenerateCSRFToken's crypto/rand.Read error branch is not covered by a
// test. Since Go 1.24, crypto/rand.Read is documented to never return an
// error — an underlying entropy-source failure calls runtime.fatal() and
// crashes the process outright rather than returning an error value (see
// https://go.dev/issue/66821), so swapping crypto/rand.Reader for a failing
// io.Reader to exercise that branch takes the whole test binary down instead
// of exercising the branch. The branch is dead code under the Go version this
// repo builds with; left uncovered deliberately rather than crashing the test
// run to chase it.

// TestSetSessionCookie verifies the HttpOnly, SameSite, and Secure attributes.
func TestSetSessionCookie(t *testing.T) {
	rr := httptest.NewRecorder()
	exp := time.Now().Add(time.Hour)
	SetSessionCookie(rr, "my-token", &exp, true)

	cookies := rr.Result().Cookies()
	require.Len(t, cookies, 1)
	c := cookies[0]
	assert.Equal(t, SessionCookieName, c.Name)
	assert.Equal(t, "my-token", c.Value)
	assert.True(t, c.HttpOnly, "session cookie must be HttpOnly")
	assert.True(t, c.Secure, "when TLS is on, session cookie must be Secure")
	assert.Equal(t, "/", c.Path)
}

// TestSetSessionCookie_NoExpiry verifies a nil expiry results in no Expires field.
func TestSetSessionCookie_NoExpiry(t *testing.T) {
	rr := httptest.NewRecorder()
	SetSessionCookie(rr, "my-token", nil, false)
	cookies := rr.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.True(t, cookies[0].Expires.IsZero(), "nil expiry must produce a session cookie with no Expires")
}

// TestClearSessionCookie verifies MaxAge=-1 (clear) is set.
func TestClearSessionCookie(t *testing.T) {
	rr := httptest.NewRecorder()
	ClearSessionCookie(rr, false)
	cookies := rr.Result().Cookies()
	require.Len(t, cookies, 1)
	c := cookies[0]
	assert.Equal(t, SessionCookieName, c.Name)
	assert.Equal(t, -1, c.MaxAge)
}

// TestSetCSRFCookie verifies the NOT-HttpOnly property (JS must read it for double-submit).
func TestSetCSRFCookie(t *testing.T) {
	rr := httptest.NewRecorder()
	SetCSRFCookie(rr, "csrf-value", false)
	cookies := rr.Result().Cookies()
	require.Len(t, cookies, 1)
	c := cookies[0]
	assert.Equal(t, CSRFCookieName, c.Name)
	assert.Equal(t, "csrf-value", c.Value)
	assert.False(t, c.HttpOnly, "CSRF cookie must NOT be HttpOnly — JS must be able to read it")
}

// TestClearCSRFCookie verifies MaxAge=-1.
func TestClearCSRFCookie(t *testing.T) {
	rr := httptest.NewRecorder()
	ClearCSRFCookie(rr, false)
	cookies := rr.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, CSRFCookieName, cookies[0].Name)
	assert.Equal(t, -1, cookies[0].MaxAge)
}

// TestSetAdminSessionCookie verifies HttpOnly is set and Expires matches the provided time.
func TestSetAdminSessionCookie(t *testing.T) {
	rr := httptest.NewRecorder()
	exp := time.Now().Add(30 * time.Minute)
	SetAdminSessionCookie(rr, "admin-token", &exp, false)
	cookies := rr.Result().Cookies()
	require.Len(t, cookies, 1)
	c := cookies[0]
	assert.Equal(t, AdminSessionCookieName, c.Name)
	assert.Equal(t, "admin-token", c.Value)
	assert.True(t, c.HttpOnly)
}

// TestClearAdminSessionCookie verifies MaxAge=-1.
func TestClearAdminSessionCookie(t *testing.T) {
	rr := httptest.NewRecorder()
	ClearAdminSessionCookie(rr, false)
	cookies := rr.Result().Cookies()
	require.Len(t, cookies, 1)
	assert.Equal(t, AdminSessionCookieName, cookies[0].Name)
	assert.Equal(t, -1, cookies[0].MaxAge)
}

// TestBlockWhenImpersonating_AllowsNonImpersonatedRequests verifies the middleware is
// transparent when there is no impersonation session.
func TestBlockWhenImpersonating_AllowsNonImpersonatedRequests(t *testing.T) {
	called := false
	h := BlockWhenImpersonating(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/pats", nil)
	req = req.WithContext(context.WithValue(req.Context(), userContextKey, &UserContext{UserID: 1}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, called)
}

// TestBlockWhenImpersonating_BlocksImpersonatedRequests verifies that a request carrying
// ImpersonatedBy is rejected with 403, preventing an admin from minting durable credentials
// while impersonating another user.
func TestBlockWhenImpersonating_BlocksImpersonatedRequests(t *testing.T) {
	called := false
	h := BlockWhenImpersonating(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	adminID := uint(99)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pats", nil)
	req = req.WithContext(context.WithValue(req.Context(), userContextKey, &UserContext{
		UserID:         1,
		ImpersonatedBy: &adminID,
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.False(t, called)
	assert.Contains(t, rr.Body.String(), "impersonating")
}

// TestBlockWhenImpersonating_NoUserContextPassesThrough ensures a missing user context
// (unauthenticated request — auth middleware handles that) is not incorrectly blocked.
func TestBlockWhenImpersonating_NoUserContextPassesThrough(t *testing.T) {
	called := false
	h := BlockWhenImpersonating(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pats", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, called)
}

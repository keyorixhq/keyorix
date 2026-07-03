package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRLRequest(userID uint) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/posture", nil)
	if userID != 0 {
		uc := &UserContext{UserID: userID}
		req = req.WithContext(context.WithValue(req.Context(), GetUserContextKey(), uc))
	}
	return req
}

// #163: disabled (the config zero value) is a transparent no-op — every request
// passes through regardless of volume.
func TestPrincipalRateLimit_DisabledIsNoOp(t *testing.T) {
	mw := PrincipalRateLimit(config.RateLimitConfig{})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	for i := 0; i < 50; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, newRLRequest(1))
		require.Equal(t, http.StatusOK, w.Code)
	}
}

// A principal exceeding their burst gets 429; a DIFFERENT principal is unaffected —
// budgets are per-principal, not shared.
func TestPrincipalRateLimit_EnforcesPerPrincipalBudget(t *testing.T) {
	mw := PrincipalRateLimit(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 3})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	// User 1 exhausts their burst of 3.
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, newRLRequest(1))
		require.Equal(t, http.StatusOK, w.Code, "request %d within burst must pass", i)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, newRLRequest(1))
	assert.Equal(t, http.StatusTooManyRequests, w.Code, "the 4th request within the same instant must be limited")
	assert.NotEmpty(t, w.Header().Get("Retry-After"))

	// User 2 has their own independent budget — unaffected by user 1's exhaustion.
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, newRLRequest(2))
	assert.Equal(t, http.StatusOK, w2.Code, "a different principal must have an independent budget")
}

// An unauthenticated request (no UserContext) falls back to an IP-keyed budget
// rather than panicking or bypassing the limiter entirely.
func TestPrincipalRateLimit_FallsBackToIPForUnauthenticated(t *testing.T) {
	mw := PrincipalRateLimit(config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 1})
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	req := newRLRequest(0)
	req.RemoteAddr = "203.0.113.5:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req)
	assert.Equal(t, http.StatusTooManyRequests, w2.Code, "a second request from the same IP within burst=1 must be limited")
}

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSCIMToken(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := SCIMToken("s3cret")(next)

	call := func(auth string) int {
		req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}

	assert.Equal(t, http.StatusOK, call("Bearer s3cret"), "valid token passes")
	assert.Equal(t, http.StatusUnauthorized, call("Bearer wrong"), "wrong token denied")
	assert.Equal(t, http.StatusUnauthorized, call(""), "missing token denied")
}

func TestSCIMToken_EmptyConfigDeniesAll(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := SCIMToken("")(next) // misconfigured: no token set

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer ")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code, "an empty configured token fails closed")
}

// G40: SCIMToken must throttle repeated failed bearer-token guesses from the same
// source IP, same as the session/PAT/machine-token path in auth.go
// (recordTokenAuthFailure / tokenAuthFailureBurst). Before the fix, a wrong SCIM
// token was simply re-evaluated as another 401 on every attempt, forever — no
// brute-force protection at all.
func TestSCIMToken_ThrottlesRepeatedFailures(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	h := SCIMToken("s3cret")(next)

	// A distinct source IP, unused by any other test in this package, so this
	// test's deliberate budget exhaustion can't pollute (or be polluted by)
	// the shared, package-global recordTokenAuthFailure limiter.
	const remoteAddr = "198.51.100.77:4242"

	call := func() int {
		req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		req.RemoteAddr = remoteAddr
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}

	// Burn through the failure budget (tokenAuthFailureBurst attempts) — each is
	// just an ordinary 401, exactly like today.
	for i := 0; i < tokenAuthFailureBurst; i++ {
		assert.Equal(t, http.StatusUnauthorized, call(), "attempt %d should still be a plain 401 within budget", i)
	}

	// The next attempt from the same IP must be throttled, not re-evaluated as
	// just another failed comparison.
	assert.Equal(t, http.StatusTooManyRequests, call(), "attempt exceeding the failure budget must be throttled")
}

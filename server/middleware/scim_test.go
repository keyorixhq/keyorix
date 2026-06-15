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

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func serve(t *testing.T, tlsEnabled bool) http.Header {
	t.Helper()
	h := SecurityHeaders(tlsEnabled)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	return rec.Header()
}

func TestSecurityHeaders_AlwaysSet(t *testing.T) {
	hdr := serve(t, false)
	assert.Equal(t, "nosniff", hdr.Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", hdr.Get("X-Frame-Options"))
	assert.Equal(t, "no-referrer", hdr.Get("Referrer-Policy"))
	// HSTS is NOT sent over plain HTTP (TLS terminated elsewhere or not at all).
	assert.Empty(t, hdr.Get("Strict-Transport-Security"))
}

func TestSecurityHeaders_HSTSOnlyWithTLS(t *testing.T) {
	hdr := serve(t, true)
	assert.Equal(t, "max-age=31536000; includeSubDomains", hdr.Get("Strict-Transport-Security"))
}

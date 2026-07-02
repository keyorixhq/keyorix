package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// RedactSensitiveURLs must rewrite RequestURI (what Logger()'s access log writes)
// for a setup-token URL, so the token never reaches the log — but must leave
// r.URL.Path (what chi routes on) untouched, and must NOT redact the
// non-token-bearing consume endpoint.
func TestRedactSensitiveURLs(t *testing.T) {
	var gotPath string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path // routing must still see the real path
		w.WriteHeader(http.StatusOK)
	})
	h := RedactSensitiveURLs(next)

	t.Run("setup token path is redacted in RequestURI", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth/setup/aBc123SuperSecretToken", nil)
		req.RequestURI = "/auth/setup/aBc123SuperSecretToken"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		assert.Equal(t, "/auth/setup/[REDACTED]", req.RequestURI, "the token must not survive into RequestURI")
		assert.NotContains(t, req.RequestURI, "aBc123SuperSecretToken")
		assert.Equal(t, "/auth/setup/aBc123SuperSecretToken", gotPath, "routing must still see the real path")
	})

	t.Run("consume endpoint (token in body, not URL) is not redacted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/auth/setup/consume", nil)
		req.RequestURI = "/auth/setup/consume"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		assert.Equal(t, "/auth/setup/consume", req.RequestURI)
	})

	t.Run("unrelated route is untouched", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1", nil)
		req.RequestURI = "/api/v1/secrets/1"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		assert.Equal(t, "/api/v1/secrets/1", req.RequestURI)
	})
}

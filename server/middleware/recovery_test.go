package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRecovery_DoesNotLeakInternals is the security invariant: a panic returns an opaque
// 500 and the response body never carries the panic value, a stack trace, or other
// internals to the client (this is a secrets manager — operators read the logs instead).
func TestRecovery_DoesNotLeakInternals(t *testing.T) {
	const sensitive = "super-secret-token-do-not-leak"
	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom: " + sensitive)
	})

	rec := httptest.NewRecorder()
	Recovery()(panicking).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/secrets/1", nil))

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	body := rec.Body.String()
	assert.NotContains(t, body, sensitive, "the panic value must never reach the client")
	for _, leak := range []string{"stack", "goroutine", "runtime.", ".go:", "boom"} {
		assert.NotContains(t, body, leak, "response must not leak internals (%q)", leak)
	}

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "InternalServerError", resp["error"])
	assert.NotContains(t, resp, "details", "no details field is ever returned")
}

// TestRecovery_PassesThroughNonPanic confirms the middleware is transparent on the happy
// path.
func TestRecovery_PassesThroughNonPanic(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	rec := httptest.NewRecorder()
	Recovery()(ok).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", strings.TrimSpace(rec.Body.String()))
}

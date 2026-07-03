package middleware

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLogger_RedactsSetupToken is the security invariant for #291: the setup/
// password-reset token in GET /auth/setup/{token} is a single-use bearer credential
// sufficient for full account takeover (the paired POST /auth/setup/consume needs
// only the token + a new password) — and the describe GET does NOT consume it. The
// global request logger must never write the raw token to the log stream (container
// logs, a log-aggregation SaaS, an on-call terminal), or a log reader could use it to
// take over the account before the legitimate recipient does.
func TestLogger_RedactsSetupToken(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	const token = "aVeryLongSingleUseSetupTokenAbc123XYZ789doNotLeak"
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/setup/"+token, nil)
	rec := httptest.NewRecorder()
	Logger()(ok).ServeHTTP(rec, req)

	logged := buf.String()
	assert.NotContains(t, logged, token, "the raw setup token must never be written to the log stream")
	assert.Contains(t, logged, "[REDACTED]", "the token segment is replaced with a fixed placeholder")
	assert.Contains(t, logged, "/auth/setup/", "the rest of the path is still logged, just not the token")
}

// TestLogger_RedactsSetupTokenUnderAPIPrefix covers the same route mounted behind
// /api/v1, in case a future deployment/proxy adds that prefix to this path.
func TestLogger_RedactsSetupTokenUnderAPIPrefix(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	const token = "anotherSingleUseTokenValueThatMustNeverLeak456"
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/setup/"+token, nil)
	rec := httptest.NewRecorder()
	Logger()(ok).ServeHTTP(rec, req)

	logged := buf.String()
	assert.NotContains(t, logged, token)
	assert.Contains(t, logged, "[REDACTED]")
}

// TestLogger_PassesThroughOrdinaryPaths confirms the redaction is scoped: an ordinary
// request path (no bearer credential embedded in it) is logged verbatim, unaffected.
func TestLogger_PassesThroughOrdinaryPaths(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/42?foo=bar", nil)
	rec := httptest.NewRecorder()
	Logger()(ok).ServeHTTP(rec, req)

	logged := buf.String()
	assert.Contains(t, logged, "/api/v1/secrets/42?foo=bar", "an ordinary path is logged unmodified")
}

// TestLogger_PassesRequestUnmodifiedToHandler confirms the redaction is purely a
// logging-side concern: the handler still sees the original, un-redacted request (the
// route dispatch and any downstream token consumption must be unaffected).
func TestLogger_PassesRequestUnmodifiedToHandler(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	const token = "handlerMustStillSeeThisRawTokenValue123"
	var seenURI string
	capture := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenURI = r.RequestURI
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/setup/"+token, nil)
	rec := httptest.NewRecorder()
	Logger()(capture).ServeHTTP(rec, req)

	assert.Equal(t, "/auth/setup/"+token, seenURI, "the handler must still receive the real, unredacted request")
}

// TestRedactSensitiveURI unit-tests the redaction helper directly, including a
// no-op case for a path with no sensitive segment.
func TestRedactSensitiveURI(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"setup token redacted", "/auth/setup/abc123", "/auth/setup/[REDACTED]"},
		{"setup token with query redacted (query string preserved)", "/auth/setup/abc123?x=1", "/auth/setup/[REDACTED]?x=1"},
		{"api-prefixed setup token redacted", "/api/v1/auth/setup/abc123", "/api/v1/auth/setup/[REDACTED]"},
		{"path shape matches even for the literal 'consume' segment (harmless: the real consume token travels in the POST body, never this GET path)", "/auth/setup/consume", "/auth/setup/[REDACTED]"},
		{"unrelated path untouched", "/api/v1/secrets/42", "/api/v1/secrets/42"},
		{"password-reset with no token segment untouched", "/auth/password-reset", "/auth/password-reset"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, redactSensitiveURI(tc.in))
		})
	}
}

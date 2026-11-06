package middleware

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedactSensitiveURI_QueryRedactedByDefault(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"allowlisted values survive", "/api/v1/audit/logs?page=2&page_size=50", "/api/v1/audit/logs?page=2&page_size=50"},
		{"unknown key value redacted, name kept", "/api/v1/x?foo=bar", "/api/v1/x?foo=[redacted]"},
		{"credential-like keys redacted", "/api/v1/x?password=hunter2&api_key=AKIAxxxx&secret=s&code=c&key=k&value=v",
			"/api/v1/x?password=[redacted]&api_key=[redacted]&secret=[redacted]&code=[redacted]&key=[redacted]&value=[redacted]"},
		{"mixed keeps safe, redacts unsafe", "/api/v1/x?limit=10&token=abc", "/api/v1/x?limit=10&token=[redacted]"},
		{"bare token redacted", "/api/v1/x?abcdef0123456789", "/api/v1/x?[redacted]"},
		{"odd key name redacted", "/api/v1/x?AKIA%20ZZ$=1", "/api/v1/x?[redacted]=[redacted]"},
		{"identity filters redacted", "/api/v1/x?username=alice&email=a@b.c&q=prod-db-pass", "/api/v1/x?username=[redacted]&email=[redacted]&q=[redacted]"},
		{"empty query dropped", "/api/v1/x?", "/api/v1/x"},
		{"existing whole-query strip still wins", "/api/v1/secrets/value?ref=prod/db", "/api/v1/secrets/value?[redacted]"},
		{"sso callback still stripped", "/api/v1/auth/sso/okta/callback?code=c&state=s", "/api/v1/auth/sso/okta/callback?[redacted]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, redactSensitiveURI(tc.in))
		})
	}
}

// The access log must never contain a caller-supplied secret placed in a query
// parameter on any route, including routes with no redaction rule of their own.
func TestLogger_NeverLogsArbitraryQuerySecret(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)

	const canary = "CANARY-9f3b7c-do-not-log"
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	for _, q := range []string{
		"password=" + canary, "api_key=" + canary, "secret=" + canary, "code=" + canary,
		"key=" + canary, "value=" + canary, "page=1&token=" + canary, canary,
		"%70assword=" + canary, // percent-encoded key name
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/1/anything?"+q, nil)
		Logger()(ok).ServeHTTP(httptest.NewRecorder(), req)
	}
	// Flush asynchronous writer, if any, by issuing one more request.
	Logger()(ok).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/flush", nil))

	assert.False(t, strings.Contains(buf.String(), canary), "a caller-supplied query secret reached the access log")
}

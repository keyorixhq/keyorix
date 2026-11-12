package middleware

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #4045: the token segment of GET /auth/setup/{token} must be redacted whole. The
// access log builds its URI from the percent-decoded path, so an encoded slash in
// the token ("%2F", any case, or a double-encoded "%252F" that decodes to a literal
// "%2F") used to end the segment early and the tail of the token was logged.
func TestLogger_RedactsWholeTokenSegmentWithEncodedSeparators(t *testing.T) {
	const head, tail = "headOfTheTokenAAAA", "tailOfTheTokenBBBB"
	cases := []struct {
		name   string
		target string
	}{
		{"plain token", "/auth/setup/" + head + tail},
		{"encoded slash upper", "/auth/setup/" + head + "%2F" + tail},
		{"encoded slash lower", "/auth/setup/" + head + "%2f" + tail},
		{"double-encoded slash", "/auth/setup/" + head + "%252F" + tail},
		{"two encoded slashes", "/auth/setup/" + head + "%2F%2F" + tail},
		{"encoded question mark", "/auth/setup/" + head + "%3F" + tail},
		{"api-prefixed encoded slash", "/api/v1/auth/setup/" + head + "%2F" + tail},
		{"encoded slash with query", "/auth/setup/" + head + "%2F" + tail + "?page=1"},
		{"invite route encoded slash", "/auth/invite/" + head + "%2F" + tail},
		{"password-reset route encoded slash", "/auth/password-reset/" + head + "%2F" + tail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)

			got := logSafeRequestURI(req)
			assert.NotContains(t, got, head)
			assert.NotContains(t, got, tail)
			assert.Contains(t, got, "[REDACTED]")

			var buf bytes.Buffer
			orig := log.Writer()
			log.SetOutput(&buf)
			defer log.SetOutput(orig)
			ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
			Logger()(ok).ServeHTTP(httptest.NewRecorder(), req)

			logged := buf.String()
			require.NotEmpty(t, logged)
			assert.NotContains(t, logged, head, "token head reached the access log")
			assert.NotContains(t, logged, tail, "token tail reached the access log")
		})
	}
}

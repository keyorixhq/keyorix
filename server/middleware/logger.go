package middleware

import (
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// sensitiveURIPattern matches request paths that carry a single-use bearer
// credential as a URL path segment — GET /auth/setup/{token} is the only such
// route in this router today (the token is sufficient, on its own, for full
// account takeover via the paired POST /auth/setup/consume), and every other
// sensitive identifier in the codebase travels in a POST body or a header, never
// a path segment. The pattern is written generally (…/setup/<tok>,
// …/invite/<tok>, …/password-reset/<tok>) so a future look-alike route is
// covered too, and is a no-op for paths that don't match (e.g. the no-token
// POST /auth/password-reset).
var sensitiveURIPattern = regexp.MustCompile(`(?i)^(/(?:api/v1/)?auth/(?:setup|invite|password-reset)/)[^/?]+`)

// sensitiveQueryPattern matches paths whose query-string parameters carry secret
// identifiers — /secrets/value and /secrets/by-name accept a ?ref= or ?name=
// query param that is the secret reference or name. Logging these verbatim would
// write secret names/references to the access log (container logs, log-aggregation
// SaaS, on-call terminal), leaking the secret catalogue to log readers.
var sensitiveQueryPattern = regexp.MustCompile(`(?i)/secrets/(?:value|by-name)\b`)

// redactSensitiveURI replaces the credential segment of a known-sensitive path
// with a fixed placeholder, and strips the entire query string for paths that
// carry secret identifiers in query parameters. It returns the input unchanged
// when no sensitive pattern matches.
func redactSensitiveURI(uri string) string {
	// First redact path-segment credentials (setup/invite/password-reset tokens).
	uri = sensitiveURIPattern.ReplaceAllString(uri, "${1}[REDACTED]")
	// Then redact query strings for endpoints that accept secret ref/name params.
	if idx := strings.IndexByte(uri, '?'); idx != -1 {
		if sensitiveQueryPattern.MatchString(uri[:idx]) {
			uri = uri[:idx] + "?[redacted]"
		}
	}
	return uri
}

// Logger returns a middleware that logs HTTP requests. It behaves like chi's
// middleware.RequestLogger(DefaultLogFormatter), except the request handed to the
// formatter has any known-sensitive path segment redacted first (see
// sensitiveURIPattern) — the original, unmodified request is still what reaches
// the route handler, so request handling is unaffected. Without this, a setup/
// password-reset token would be written to the log stream (container logs, a
// log-aggregation SaaS, an on-call terminal) in plaintext on every hit, and that
// token remains live (the describe GET does not consume it) — a log reader could
// use it for account takeover.
func Logger() func(next http.Handler) http.Handler {
	formatter := &middleware.DefaultLogFormatter{
		Logger:  log.Default(),
		NoColor: false,
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logReq := r
			if redacted := redactSensitiveURI(r.RequestURI); redacted != r.RequestURI {
				clone := r.Clone(r.Context())
				clone.RequestURI = redacted
				logReq = clone
			}
			entry := formatter.NewLogEntry(logReq)
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			t1 := time.Now()
			defer func() {
				entry.Write(ww.Status(), ww.BytesWritten(), ww.Header(), time.Since(t1), nil)
			}()

			next.ServeHTTP(ww, middleware.WithLogEntry(r, entry))
		})
	}
}

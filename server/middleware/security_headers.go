package middleware

import "net/http"

// SecurityHeaders sets standard hardening response headers on every response. For a
// secrets manager these matter beyond the usual:
//   - X-Content-Type-Options: nosniff — never let a browser MIME-sniff a response into
//     something executable.
//   - X-Frame-Options: DENY — the dashboard must never be framed (clickjacking).
//   - Referrer-Policy: no-referrer — never leak the request URL via the Referer header;
//     Keyorix URLs can carry tokens (e.g. the SSO completion fragment), so stripping the
//     referrer closes a token-leak channel to third-party pages.
//
// HSTS is sent only when this process terminates TLS (tlsEnabled); deployments that
// terminate TLS at a proxy add HSTS there, and sending it over plain HTTP is wrong.
//
// Headers are set before the handler runs, so they apply to every response — including
// errors, panics (the recovery middleware runs after this), and static assets — not just
// the handlers that set nosniff themselves today.
func SecurityHeaders(tlsEnabled bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "no-referrer")
			if tlsEnabled {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

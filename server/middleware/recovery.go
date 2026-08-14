package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"runtime/debug"
	"strings"
	"unicode"
)

// stripControl removes control characters (CR/LF, ANSI/C1 escapes, NUL, etc.) from a
// string before it is written to a log line, preventing log-injection / terminal-control
// smuggling via attacker-influenceable values (request headers, usernames).
func stripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

// Recovery returns a middleware that recovers from panics and returns a proper error response
func Recovery() func(next http.Handler) http.Handler { // NOSONAR -- cognitive complexity 20, suppress go:S3776
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					// Log the panic with stack trace
					log.Printf("PANIC: %v\n%s", err, debug.Stack())

					// Get request context for logging
					// Strip control characters from the attacker-influenceable X-Request-ID
					// header and the username before logging, so neither can inject a forged
					// log line or smuggle terminal-control sequences into a log viewer
					// (net/http already drops CR/LF in headers, but not other C0/C1 controls).
					requestID := stripControl(r.Header.Get("X-Request-ID"))
					if requestID == "" {
						requestID = "unknown"
					}

					var userInfo string
					if userCtx := GetUserFromContext(r.Context()); userCtx != nil {
						userInfo = stripControl(userCtx.Username)
					} else {
						userInfo = "anonymous"
					}

					// #G29: this used to log r.URL.Path raw, bypassing redaction
					// entirely — a panic mid-request to e.g. GET /auth/setup/{token}
					// or the SSO callback (?code=...) would write that credential
					// straight to the panic log. logSafeRequestURI (logger.go) is
					// the SAME canonicalizing redact+strip-control function the
					// access log uses, so this can't independently drift out of
					// sync with it.
					log.Printf("PANIC CONTEXT: RequestID=%s, User=%s, Method=%s, Path=%s, RemoteAddr=%s",
						requestID, userInfo, r.Method, logSafeRequestURI(r), r.RemoteAddr)

					// Send a generic error response. We deliberately NEVER return the
					// panic value, stack trace, or other internals to the client — this
					// is a secrets manager, and a panic value can carry sensitive data;
					// leaking internals (even gated behind a "dev mode" flag) is a foot-
					// gun one config toggle away from production. Operators get the full
					// panic + stack from the logs above; clients get only an opaque 500.
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)

					response := map[string]interface{}{
						"error":   "InternalServerError",
						"message": "An internal server error occurred",
						"code":    http.StatusInternalServerError,
					}

					if encodeErr := json.NewEncoder(w).Encode(response); encodeErr != nil {
						log.Printf("Failed to encode panic response: %v", encodeErr)
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					}
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

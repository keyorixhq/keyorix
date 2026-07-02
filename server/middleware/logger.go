package middleware

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// Logger returns a middleware that logs HTTP requests
func Logger() func(next http.Handler) http.Handler {
	return middleware.RequestLogger(&middleware.DefaultLogFormatter{
		Logger:  log.Default(),
		NoColor: false,
	})
}

// sensitiveURLPathPrefixes lists path prefixes whose remainder is a
// bearer-equivalent credential embedded in the URL — a setup token, delivered as
// a user-facing "click this link" URL, so it can't simply move to a header/body
// like every other credential in this app. Proxies/load balancers/browser
// history already see it in the URL; this server's own access log (Logger,
// above) must not compound that by writing the token to disk/stdout too.
var sensitiveURLPathPrefixes = []string{"/auth/setup/"}

// setupConsumePath is the one route under sensitiveURLPathPrefixes that does NOT
// carry a token in its path (the token there is in the POST body) and so is
// exempt from redaction.
const setupConsumePath = "/auth/setup/consume"

// RedactSensitiveURLs replaces r.RequestURI — the raw request line Logger()
// formats into the access log — with a redacted placeholder for routes matched
// by sensitiveURLPathPrefixes, before the request reaches Logger(). It must run
// BEFORE Logger() in the middleware chain. Only RequestURI (used for display) is
// rewritten, never r.URL.Path (used for chi's route matching), so request
// handling is unaffected.
func RedactSensitiveURLs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, prefix := range sensitiveURLPathPrefixes {
			if strings.HasPrefix(r.URL.Path, prefix) && r.URL.Path != setupConsumePath {
				r.RequestURI = prefix + "[REDACTED]"
				break
			}
		}
		next.ServeHTTP(w, r)
	})
}

// CustomLogger returns a custom logging middleware with more detailed information
func CustomLogger() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Create a response writer wrapper to capture status code
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			// Get request ID if available
			requestID := middleware.GetReqID(r.Context())

			// Get user context if available
			var userID uint
			var username string
			if userCtx := GetUserFromContext(r.Context()); userCtx != nil {
				userID = userCtx.UserID
				username = userCtx.Username
			}

			// Process request
			next.ServeHTTP(ww, r)

			// Log request details
			duration := time.Since(start)

			log.Printf( // #nosec G706
				"[%s] %s %s %d %s - User: %s(%d) - %s - %s",
				requestID,
				r.Method,
				r.URL.Path,
				ww.Status(),
				duration,
				username,
				userID,
				r.RemoteAddr,
				r.UserAgent(),
			)

			// Log slow requests (>1 second)
			if duration > time.Second {
				log.Printf("SLOW REQUEST: %s %s took %s", r.Method, r.URL.Path, duration) // #nosec G706
			}

			// Log errors
			if ww.Status() >= 400 {
				log.Printf("ERROR RESPONSE: %s %s returned %d", r.Method, r.URL.Path, ww.Status()) // #nosec G706
			}
		})
	}
}

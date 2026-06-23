package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"runtime/debug"
)

// Recovery returns a middleware that recovers from panics and returns a proper error response
func Recovery() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					// Log the panic with stack trace
					log.Printf("PANIC: %v\n%s", err, debug.Stack())

					// Get request context for logging
					requestID := r.Header.Get("X-Request-ID")
					if requestID == "" {
						requestID = "unknown"
					}

					var userInfo string
					if userCtx := GetUserFromContext(r.Context()); userCtx != nil {
						userInfo = userCtx.Username
					} else {
						userInfo = "anonymous"
					}

					log.Printf("PANIC CONTEXT: RequestID=%s, User=%s, Method=%s, Path=%s, RemoteAddr=%s", // #nosec G706
						requestID, userInfo, r.Method, r.URL.Path, r.RemoteAddr)

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

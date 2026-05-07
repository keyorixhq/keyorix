package middleware

import (
	"log"
	"net/http"
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

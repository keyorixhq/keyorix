package middleware

import "net/http"

// MaxBodyBytes caps each request body at limit bytes via http.MaxBytesReader, so a
// handler that decodes r.Body (every JSON endpoint) can't be made to buffer an arbitrary
// amount of attacker-supplied data — a cheap memory-exhaustion DoS otherwise. When the
// cap is exceeded, reads fail and the handler's decode returns an error (a 4xx), and the
// server sends a 413. A limit <= 0 disables the cap (passthrough).
func MaxBodyBytes(limit int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if limit > 0 && r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, limit)
			}
			next.ServeHTTP(w, r)
		})
	}
}

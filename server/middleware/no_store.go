package middleware

import "net/http"

// NoStore sets Cache-Control: no-store on every response it wraps, so browsers, proxies,
// and any shared cache never store the body. API responses here can carry secret values,
// tokens, and other sensitive data; without this they have no Cache-Control and are
// cacheable by default. Apply it to the API groups (before auth, so even a 401 carries
// it). Static assets keep their own cache headers — this is scoped to the API.
func NoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

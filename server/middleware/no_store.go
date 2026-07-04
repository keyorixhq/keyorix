package middleware

import "net/http"

// NoStore sets Cache-Control: no-store on every response it wraps, so browsers, proxies,
// and any shared cache never store the body. Many responses in this codebase carry secret
// values, tokens, and other sensitive data; without this they have no Cache-Control and are
// cacheable by default. Registered as a global, top-level router middleware (#433) rather
// than on specific route groups, so nothing registered later is silently missed. A handler
// that deliberately wants a different policy (the health/readiness checks' own "no-cache",
// the web UI's hashed static assets, the SPA shell) sets Cache-Control itself further down
// the chain and wins, since http.Header.Set replaces rather than appends.
func NoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

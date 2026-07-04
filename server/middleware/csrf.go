package middleware

import (
	"crypto/subtle"
	"net/http"
)

// csrfProtectedMethods are the state-changing methods that require a matching
// X-CSRF-Token header once cookie-based auth is in play. GET/HEAD/OPTIONS never
// mutate state, so they're exempt (and must stay exempt — CSRF-protecting a safe
// method would just break normal navigation/prefetch with no security benefit).
var csrfProtectedMethods = map[string]bool{
	http.MethodPost:   true,
	http.MethodPut:    true,
	http.MethodPatch:  true,
	http.MethodDelete: true,
}

// RequireCSRF enforces the double-submit cookie pattern: a state-changing request
// must echo the csrf_token cookie's value back as the X-CSRF-Token header, or it's
// rejected. This is only meaningful — and only checked — for requests carrying the
// session cookie: a pure-Bearer caller (PAT, machine token, CI/API client) is immune
// to CSRF by construction, since a browser can't be tricked into sending a custom
// header cross-site without this app's CORS config allowlisting the attacker's
// origin (it allowlists none). Requiring the header only for cookie-authenticated
// requests also means the header/cookie value comparison never runs, and a missing
// CSRF cookie never wrongly rejects, a plain Bearer request.
func RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !csrfProtectedMethods[r.Method] {
			next.ServeHTTP(w, r)
			return
		}

		sessionCookie, err := r.Cookie(SessionCookieName)
		if err != nil || sessionCookie.Value == "" {
			// No session cookie on this request — Bearer-only caller, not subject to CSRF.
			next.ServeHTTP(w, r)
			return
		}

		csrfCookie, err := r.Cookie(CSRFCookieName)
		if err != nil || csrfCookie.Value == "" {
			forbiddenResponse(w, "Missing CSRF token")
			return
		}

		headerValue := r.Header.Get(CSRFHeaderName)
		if headerValue == "" {
			forbiddenResponse(w, "Missing CSRF token header")
			return
		}

		if subtle.ConstantTimeCompare([]byte(headerValue), []byte(csrfCookie.Value)) != 1 {
			forbiddenResponse(w, "CSRF token mismatch")
			return
		}

		next.ServeHTTP(w, r)
	})
}

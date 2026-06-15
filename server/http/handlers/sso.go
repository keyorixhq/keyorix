// sso.go — human SSO login endpoints (OIDC authorization-code flow). All three are
// unauthenticated (mounted outside the session middleware): the login redirect, the
// IdP callback, and the provider list the login page reads. On success the callback
// hands the SPA its session by redirecting to the web completion page with the token
// in the URL fragment (kept out of server logs / the Referer header).
package handlers

import (
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
)

// ListSSOProviders handles GET /auth/sso/providers — the enabled provider names, so
// the login page can render the right "Sign in with …" buttons.
func (h *AuthHandler) ListSSOProviders(w http.ResponseWriter, _ *http.Request) {
	sendSuccess(w, map[string]interface{}{"providers": h.coreService.SSOProviderNames()}, "")
}

// BeginSSO handles GET /auth/sso/{provider}/login — redirects the browser to the IdP
// authorization endpoint with a fresh state + nonce.
func (h *AuthHandler) BeginSSO(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	authURL, err := h.coreService.BeginSSO(r.Context(), provider, r.URL.Query().Get("return_to"))
	if err != nil {
		sendError(w, "SSOError", err.Error(), http.StatusBadRequest, nil)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// CompleteSSO handles GET /auth/sso/{provider}/callback — exchanges the code, mints a
// session, and redirects to the SPA completion page with the token in the fragment.
func (h *AuthHandler) CompleteSSO(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	completeURL, ok := h.coreService.SSOCompleteURL(provider)
	if !ok {
		sendError(w, "SSOError", "unknown SSO provider", http.StatusBadRequest, nil)
		return
	}

	q := r.URL.Query()
	if errParam := q.Get("error"); errParam != "" {
		// The IdP itself reported an error (e.g. access_denied).
		h.redirectFragment(w, r, completeURL, url.Values{"error": {errParam}})
		return
	}
	code, state := q.Get("code"), q.Get("state")
	if code == "" || state == "" {
		h.redirectFragment(w, r, completeURL, url.Values{"error": {"missing code or state"}})
		return
	}

	session, _, returnTo, err := h.coreService.CompleteSSO(r.Context(), provider, code, state, r.Header.Get("User-Agent"), r.RemoteAddr)
	if err != nil {
		h.redirectFragment(w, r, completeURL, url.Values{"error": {err.Error()}})
		return
	}

	frag := url.Values{"token": {session.SessionToken}}
	if session.ExpiresAt != nil {
		frag.Set("expires_at", session.ExpiresAt.Format(time.RFC3339))
	}
	if session.AbsoluteExpiresAt != nil {
		frag.Set("absolute_expires_at", session.AbsoluteExpiresAt.Format(time.RFC3339))
	}
	if returnTo != "" {
		frag.Set("return_to", returnTo)
	}
	h.redirectFragment(w, r, completeURL, frag)
}

// redirectFragment 302-redirects to base#<encoded values>, delivering the token (or
// an error) to the SPA without it touching query logs.
func (h *AuthHandler) redirectFragment(w http.ResponseWriter, r *http.Request, base string, values url.Values) {
	http.Redirect(w, r, base+"#"+values.Encode(), http.StatusFound)
}

package middleware

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"time"
)

// SessionCookieName and CSRFCookieName are the two cookies issued alongside a
// session: the session cookie carries the opaque session token and is HttpOnly
// (never JS-readable, closing the XSS-blast-radius gap the localStorage-token
// design had); the CSRF cookie is deliberately readable by JS so it can be
// echoed back as CSRFHeaderName on state-changing requests (double-submit
// pattern) — see RequireCSRF in csrf.go.
const (
	SessionCookieName = "kx_session"
	CSRFCookieName    = "csrf_token"
	CSRFHeaderName    = "X-CSRF-Token"

	// AdminSessionCookieName stashes an admin's own session token, plaintext,
	// while they're impersonating another user — set alongside the swap to the
	// impersonation session's SessionCookieName, cleared when impersonation ends.
	// This is how "return to admin" is restored under hashed-at-rest session
	// storage: the server never retains a plaintext token after issuing it (see
	// local_auth.go's hashSessionToken), so it can't recall the admin's original
	// token from the database once impersonation has started — only the browser,
	// which received it live, still has it. Round-tripping it through a second
	// HttpOnly cookie (never JS-readable, so this doesn't reopen the exposure the
	// cookie migration closed) lets End validate-and-restore it without the
	// server ever needing to store or recover a plaintext value itself.
	AdminSessionCookieName = "kx_admin_session"
)

// SetSessionCookie issues (or rotates) the HttpOnly session cookie. SameSite=Lax,
// not Strict: Strict drops the cookie on a top-level cross-site navigation into
// the app (a bookmarked link, an emailed deep link, the redirect back from an
// OIDC/SAML IdP), forcing a spurious re-login even with a live session — Lax
// already blocks the cross-site POST case CSRF actually depends on. expiresAt
// nil means no absolute ceiling for this session (matches the existing
// AbsoluteExpiresAt semantics) — the cookie is then a browser-session cookie
// with no Expires/Max-Age, cleared when the browser closes.
func SetSessionCookie(w http.ResponseWriter, token string, expiresAt *time.Time, secure bool) {
	cookie := &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
	if expiresAt != nil {
		cookie.Expires = *expiresAt
	}
	http.SetCookie(w, cookie)
}

// ClearSessionCookie expires the session cookie immediately (logout, or the
// gone-original-session case when ending impersonation).
func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// SetCSRFCookie issues (or rotates) the CSRF double-submit cookie. Not HttpOnly
// — the SPA reads it and echoes it back as CSRFHeaderName; the security
// property comes from a cross-site attacker being unable to read or set a
// custom header on a request to this origin (no third-party origin is
// allowlisted by this app's CORS config), not from the cookie being secret.
func SetCSRFCookie(w http.ResponseWriter, token string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearCSRFCookie expires the CSRF cookie (logout).
func ClearCSRFCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// SetAdminSessionCookie stashes the admin's own session token while they
// impersonate another user. expiresAt should match the impersonation session's
// own expiry, so the stash cookie never outlives the impersonation window it
// belongs to (see AdminSessionCookieName's doc comment for why this exists).
func SetAdminSessionCookie(w http.ResponseWriter, token string, expiresAt *time.Time, secure bool) {
	cookie := &http.Cookie{
		Name:     AdminSessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
	if expiresAt != nil {
		cookie.Expires = *expiresAt
	}
	http.SetCookie(w, cookie)
}

// ClearAdminSessionCookie removes the stashed admin session cookie once
// impersonation ends (restored or not).
func ClearAdminSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     AdminSessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// GenerateCSRFToken creates a cryptographically random 32-byte hex token, mirroring
// internal/core's unexported generateSecureToken (duplicated rather than exported
// solely for this — it's a two-line primitive, not shared state).
func GenerateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

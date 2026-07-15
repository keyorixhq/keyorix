package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)


// checkLoginRateLimit returns true if the IP has exceeded the login-attempt budget
// within the window. Backed by the DB so the limit holds across HA replicas
// (ADR-040). Fails open on a storage error — it's a backstop on top of the real
// credential check, not the auth gate itself.
func (h *AuthHandler) checkLoginRateLimit(ctx context.Context, ip string) bool {
	return h.coreService.IsLoginRateLimited(ctx, ip)
}

// recordLoginAttempt records a failed login attempt for the IP (best-effort).
func (h *AuthHandler) recordLoginAttempt(ctx context.Context, ip string) {
	h.coreService.RecordFailedLogin(ctx, ip)
}

// AuthHandler handles authentication HTTP requests.
type AuthHandler struct {
	coreService *core.KeyorixCore
	// tlsEnabled gates the Secure attribute on the session/CSRF cookies, same
	// signal SecurityHeaders uses for HSTS — set only when this process itself
	// terminates TLS (a proxy-terminated deployment sets it there instead).
	tlsEnabled bool
}

// NewAuthHandler constructs an AuthHandler.
func NewAuthHandler(coreService *core.KeyorixCore, tlsEnabled bool) *AuthHandler {
	return &AuthHandler{coreService: coreService, tlsEnabled: tlsEnabled}
}

// setSessionCookies issues the session + CSRF cookies for a freshly
// created/rotated session. Best-effort on CSRF token generation failure: log
// and continue without one rather than fail the whole login/refresh — the
// session cookie is what actually matters for authentication; a missing CSRF
// cookie only blocks this browser's own subsequent state-changing requests
// until it retries, it doesn't grant an attacker anything.
func (h *AuthHandler) setSessionCookies(w http.ResponseWriter, session *models.Session) {
	middleware.SetSessionCookie(w, session.SessionToken, session.ExpiresAt, h.tlsEnabled)
	if csrfToken, err := middleware.GenerateCSRFToken(); err == nil {
		middleware.SetCSRFCookie(w, csrfToken, h.tlsEnabled)
	}
}

// ── Request / response shapes ─────────────────────────────────────────────────

type loginRequestBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponseBody struct {
	Token string `json:"token"`
	// ExpiresAt is when the current access token lapses — the client should refresh
	// silently before this. AbsoluteExpiresAt, when present, is the hard ceiling
	// past which refresh is refused and the user must re-authenticate.
	ExpiresAt         string   `json:"expires_at,omitempty"`
	AbsoluteExpiresAt string   `json:"absolute_expires_at,omitempty"`
	UserID            uint     `json:"user_id"`
	Username          string   `json:"username"`
	Email             string   `json:"email"`
	DisplayName       string   `json:"display_name"`
	Role              string   `json:"role"`        // primary (highest-privilege) role
	Roles             []string `json:"roles"`       // all assigned role names
	Permissions       []string `json:"permissions"` // distinct permissions across roles
	// PasswordChangeRequired is true when the password has exceeded the policy's
	// max age (ADR-025 max_age_days) or the account is in a restricted state — the
	// UI should route to change-password.
	PasswordChangeRequired bool   `json:"password_change_required,omitempty"`
	AccountState           string `json:"account_state,omitempty"`
}

type passwordResetRequestBody struct {
	Email string `json:"email"`
}

type initSystemRequestBody struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	Token       string `json:"bootstrap_token"`
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// Login handles POST /auth/login.
// Accepts username + password, returns a session token on success.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	// Rate limit by IP — max 10 failed attempts per 15 minutes
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	if h.checkLoginRateLimit(r.Context(), ip) {
		sendError(w, "TooManyRequests", "Too many login attempts. Try again later.", http.StatusTooManyRequests, nil)
		return
	}

	var body loginRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}

	session, user, err := h.coreService.Login(r.Context(), &core.LoginRequest{
		Username:  body.Username,
		Password:  body.Password,
		UserAgent: r.Header.Get(hdrUserAgent),
		IPAddress: ip,
	})
	if err != nil {
		// MFA-enabled account: the password was correct but a second factor is
		// required. Issue a short-lived challenge instead of a session.
		if errors.Is(err, core.ErrMFARequired) {
			challenge, cerr := h.coreService.CreateMFAChallenge(r.Context(), user.ID)
			if cerr != nil {
				sendError(w, "Internal", "failed to start MFA challenge", http.StatusInternalServerError, nil)
				return
			}
			// Tell the client which second factors this account can complete, so it
			// can offer the right step (TOTP code entry vs. a passkey prompt).
			sendSuccess(w, map[string]interface{}{
				"mfa_required":       true,
				"mfa_challenge":      challenge,
				"totp_available":     user.MFAEnabled,
				"webauthn_available": user.WebAuthnEnabled,
			}, "MFA required")
			return
		}
		h.recordLoginAttempt(r.Context(), ip)
		goSafe(func() { h.coreService.LogAuthFailure(context.Background(), body.Username, ip) }) // #nosec G118
		sendError(w, "Unauthorized", "Invalid credentials", http.StatusUnauthorized, nil)
		return
	}

	resp := h.buildLoginResponse(r.Context(), session, user)
	h.setSessionCookies(w, session)

	// Audit log + last-login stamp (both non-blocking)
	ip, ua := r.RemoteAddr, r.Header.Get(hdrUserAgent)
	goSafe(func() { h.coreService.LogAuthLogin(context.Background(), user.ID, user.Username, ip, ua) }) // #nosec G118
	goSafe(func() { _ = h.coreService.RecordLogin(context.Background(), user.ID) })                     // #nosec G118

	sendSuccess(w, resp, "Login successful")
}

// buildLoginResponse assembles the session-token + identity payload returned on a
// successful login. Shared with the setup-token consume flow so that "landing the
// user logged in" yields exactly the same shape a normal login does.
func (h *AuthHandler) buildLoginResponse(ctx context.Context, session *models.Session, user *models.User) loginResponseBody {
	resp := loginResponseBody{
		Token:       session.SessionToken,
		UserID:      user.ID,
		Username:    user.Username,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Roles:       []string{},
		Permissions: []string{},
	}
	if session.ExpiresAt != nil {
		resp.ExpiresAt = session.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if session.AbsoluteExpiresAt != nil {
		resp.AbsoluteExpiresAt = session.AbsoluteExpiresAt.UTC().Format(time.RFC3339)
	}
	// Surface roles + permissions so the UI can gate nav/routes. Best-effort:
	// a failure here must not block an otherwise-successful login.
	if id, ierr := h.coreService.GetUserIdentity(ctx, user.ID); ierr == nil {
		resp.Role, resp.Roles, resp.Permissions = id.Role, id.Roles, id.Permissions
	}
	// Flag an expired/required password change so the UI can route (ADR-025).
	resp.AccountState = core.NormalizeAccountState(user.AccountState)
	resp.PasswordChangeRequired = h.coreService.PasswordExpired(user) || core.AccountRestricted(user.AccountState)
	return resp
}

// ── Setup-token endpoints (ADR-028) ─────────────────────────────────────────────

type setupTokenInfoResponse struct {
	Purpose     string `json:"purpose"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name,omitempty"`
}

type consumeSetupRequestBody struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// GetSetupToken handles GET /auth/setup/{token}: it validates the single-use setup
// token (without consuming it) and returns a non-sensitive description so the
// landing page can render the right form. A dead token (unknown/expired/used)
// returns 410 Gone.
func (h *AuthHandler) GetSetupToken(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	if token == "" {
		sendError(w, "BadRequest", "Missing setup token", http.StatusBadRequest, nil)
		return
	}
	info, err := h.coreService.DescribeSetupToken(r.Context(), token)
	if err != nil {
		sendError(w, "Gone", "This setup link is no longer valid", http.StatusGone, nil)
		return
	}
	sendSuccess(w, setupTokenInfoResponse{
		Purpose:     info.Purpose,
		Email:       info.Email,
		DisplayName: info.DisplayName,
	}, "")
}

// ConsumeSetup handles POST /auth/setup/consume: it consumes the single-use setup
// token, sets the user's password, and lands them logged in with a fresh session —
// the same response shape as a normal login.
func (h *AuthHandler) ConsumeSetup(w http.ResponseWriter, r *http.Request) {
	var body consumeSetupRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	if body.Token == "" || body.Password == "" {
		sendError(w, "BadRequest", "Token and password are required", http.StatusBadRequest, nil)
		return
	}

	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	result, err := h.coreService.CompleteSetup(r.Context(), body.Token, body.Password, r.Header.Get(hdrUserAgent), ip) // nosemgrep: trailofbits.go.invalid-usage-of-modified-variable.invalid-usage-of-modified-variable -- ErrMFARequired is a sentinel that carries a valid result.User
	if err != nil {
		// The new password was accepted, but the account has MFA (TOTP) or a passkey
		// enrolled — mirror Login's ErrMFARequired handling exactly (see Login above)
		// so a password reset cannot be used to silently bypass the second factor.
		// Issue a short-lived challenge instead of a session; the client completes
		// VerifyMFALogin (or the WebAuthn ceremony) to get a real session.
		if errors.Is(err, core.ErrMFARequired) {
			challenge, cerr := h.coreService.CreateMFAChallenge(r.Context(), result.User.ID)
			if cerr != nil {
				sendError(w, "Internal", "failed to start MFA challenge", http.StatusInternalServerError, nil)
				return
			}
			sendSuccess(w, map[string]interface{}{
				"mfa_required":       true,
				"mfa_challenge":      challenge,
				"totp_available":     result.User.MFAEnabled,
				"webauthn_available": result.User.WebAuthnEnabled,
			}, "MFA required")
			return
		}
		// Only a password-policy failure surfaces its reason (the link is still live,
		// so the user can fix the password and retry). Every other failure — dead/used
		// token, missing or already-existing account, internal error — is reported
		// generically so this unauthenticated endpoint is not an account-existence or
		// internal-error oracle.
		if errors.Is(err, core.ErrInvalidSetupPassword) {
			sendError(w, "BadRequest", err.Error(), http.StatusBadRequest, nil)
			return
		}
		sendError(w, "BadRequest", "This setup link could not be completed. It may be invalid or expired — ask your administrator for a new one.", http.StatusBadRequest, nil)
		return
	}

	resp := h.buildLoginResponse(r.Context(), result.Session, result.User)
	h.setSessionCookies(w, result.Session)
	goSafe(func() {
		h.coreService.LogAuthLogin(context.Background(), result.User.ID, result.User.Username, ip, r.Header.Get(hdrUserAgent))
	}) // #nosec G118
	goSafe(func() { _ = h.coreService.RecordLogin(context.Background(), result.User.ID) }) // #nosec G118

	sendSuccess(w, resp, "Account setup complete")
}

// Logout handles POST /auth/logout.
// Invalidates the Bearer token supplied in the Authorization header.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		sendError(w, "BadRequest", "Missing authorization token", http.StatusBadRequest, nil)
		return
	}

	// Look up the session owner before invalidating so the audit log has a user ID.
	logoutUserID, logoutUsername := h.coreService.LookupSessionUser(r.Context(), token)

	if err := h.coreService.Logout(r.Context(), token); err != nil {
		sendError(w, "InternalError", "Failed to logout", http.StatusInternalServerError, nil)
		return
	}

	// Evict from auth cache immediately so the token is rejected without a DB hit.
	middleware.InvalidateTokenCache(token)
	middleware.ClearSessionCookie(w, h.tlsEnabled)
	middleware.ClearCSRFCookie(w, h.tlsEnabled)

	// Audit log (non-blocking)
	ip, ua := r.RemoteAddr, r.Header.Get(hdrUserAgent)
	goSafe(func() { h.coreService.LogAuthLogout(context.Background(), logoutUserID, logoutUsername, ip, ua) }) // #nosec G118

	sendSuccess(w, nil, "Logged out successfully")
}

// RefreshToken handles POST /auth/refresh.
// Issues a new session token and invalidates the old one.
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		sendError(w, "BadRequest", "Missing authorization token", http.StatusBadRequest, nil)
		return
	}

	session, err := h.coreService.RefreshSession(r.Context(), token)
	if err != nil {
		sendError(w, "Unauthorized", "Session not found or expired", http.StatusUnauthorized, nil)
		return
	}

	// Token rotation: evict the OLD token from the auth cache immediately, like Logout
	// and ChangePassword. Without this, the just-validated old token lingers in the 30s
	// positive cache and keeps passing auth (a cache hit skips the DB) even though its
	// session row was deleted — so it stays usable for up to validTokenTTL after being
	// rotated away.
	middleware.InvalidateTokenCache(token)
	h.setSessionCookies(w, session)

	resp := map[string]interface{}{
		"token": session.SessionToken,
	}
	if session.ExpiresAt != nil {
		resp["expires_at"] = session.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if session.AbsoluteExpiresAt != nil {
		resp["absolute_expires_at"] = session.AbsoluteExpiresAt.UTC().Format(time.RFC3339)
	}

	sendSuccess(w, resp, "Token refreshed")
}

// Profile handles GET /auth/profile.
// Returns the current authenticated user's profile.
func (h *AuthHandler) Profile(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	user, err := h.coreService.GetUser(r.Context(), userCtx.UserID)
	if err != nil {
		sendError(w, "NotFound", "User not found", http.StatusNotFound, nil)
		return
	}

	profile := userProfileMap(user, h.userIdentity(r, userCtx.UserID))
	// Surface impersonation state from the server-validated session (UserContext.
	// ImpersonatedBy, resolved by the auth middleware) rather than requiring the
	// client to track it itself — under cookie auth the client has no token to
	// inspect, so this is now the only source of truth for "am I impersonating,
	// and who is the real admin" (used to render the impersonation banner).
	if userCtx.ImpersonatedBy != nil {
		if admin, aerr := h.coreService.GetUser(r.Context(), *userCtx.ImpersonatedBy); aerr == nil {
			profile["impersonation"] = map[string]interface{}{
				"admin_id":           admin.ID,
				"admin_username":     admin.Username,
				"admin_display_name": admin.DisplayName,
			}
		}
	}
	sendSuccess(w, profile, "")
}

// userIdentity returns the user's role/permission summary for the profile DTO.
// Best-effort: on error it returns an empty identity so the profile still renders.
func (h *AuthHandler) userIdentity(r *http.Request, userID uint) core.UserIdentity {
	id, err := h.coreService.GetUserIdentity(r.Context(), userID)
	if err != nil {
		return core.UserIdentity{Roles: []string{}, Permissions: []string{}}
	}
	return id
}

// userProfileMap is the shared self-profile DTO returned by GET and PUT /auth/profile.
func userProfileMap(user *models.User, id core.UserIdentity) map[string]interface{} {
	roles, permissions := id.Roles, id.Permissions
	if roles == nil {
		roles = []string{}
	}
	if permissions == nil {
		permissions = []string{}
	}
	profile := map[string]interface{}{
		"id":            user.ID,
		"username":      user.Username,
		"email":         user.Email,
		"display_name":  user.DisplayName,
		"is_active":     user.IsActive,
		"created_at":    user.CreatedAt,
		"last_login_at": nil,
		"role":          id.Role,
		"roles":         roles,
		"permissions":   permissions,
	}
	if user.LastLoginAt != nil {
		profile["last_login_at"] = user.LastLoginAt.UTC().Format(time.RFC3339)
	}
	return profile
}

// updateProfileRequestBody is the self-service profile update — only the fields a
// user may change about themselves. Username/role/active are intentionally absent.
// CurrentPassword is required only when Email changes (mirrors changePasswordRequestBody's
// re-authentication check); a display-name-only update needs no password.
type updateProfileRequestBody struct {
	DisplayName     string `json:"display_name"`
	Email           string `json:"email"`
	CurrentPassword string `json:"current_password,omitempty"`
}

// UpdateProfile handles PUT /auth/profile — self-scoped display name + email update.
// Changing the email additionally requires the caller's current password: the email is
// the anchor for password-reset delivery and SSO account linking, so a hijacked session
// must not be able to silently repoint it to an attacker-controlled address.
func (h *AuthHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body updateProfileRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}

	user, err := h.coreService.UpdateOwnProfile(r.Context(), userCtx.UserID, body.DisplayName, body.Email, body.CurrentPassword)
	if err != nil {
		if strings.Contains(err.Error(), "incorrect") {
			sendError(w, "Unauthorized", "Current password is incorrect", http.StatusUnauthorized, nil)
			return
		}
		if strings.Contains(err.Error(), "already exists") {
			sendError(w, "Conflict", "That email is already in use", http.StatusConflict, nil)
			return
		}
		sendError(w, "BadRequest", "Failed to update profile", http.StatusBadRequest, nil)
		return
	}

	sendSuccess(w, userProfileMap(user, h.userIdentity(r, userCtx.UserID)), "Profile updated")
}

type changePasswordRequestBody struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// ChangePassword handles POST /auth/change-password. On success the caller's other
// sessions are dropped, but the current session (this bearer token) stays valid.
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body changePasswordRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}

	token := extractBearerToken(r)
	err := h.coreService.ChangePassword(r.Context(), userCtx.UserID, body.CurrentPassword, body.NewPassword, token)
	if err != nil {
		if strings.Contains(err.Error(), "incorrect") {
			sendError(w, "Unauthorized", "Current password is incorrect", http.StatusUnauthorized, nil)
			return
		}
		sendError(w, "BadRequest", err.Error(), http.StatusBadRequest, nil)
		return
	}
	// Evict the cached identity so a restriction cleared by this change (ADR-025)
	// takes effect on the next request instead of lingering for the cache TTL.
	middleware.InvalidateTokenCache(token)
	sendSuccess(w, nil, "Password changed")
}

// sessionResponse is the safe DTO for a session — never exposes the token.
type sessionResponse struct {
	ID         uint    `json:"id"`
	UserAgent  string  `json:"user_agent"`
	IPAddress  string  `json:"ip_address"`
	CreatedAt  string  `json:"created_at"`
	ExpiresAt  *string `json:"expires_at"`
	LastSeenAt *string `json:"last_seen_at"`
	Current    bool    `json:"current"`
}

// ListSessions handles GET /auth/sessions — the caller's active sessions, with the
// session backing the current request flagged as current.
func (h *AuthHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	sessions, err := h.coreService.ListOwnSessions(r.Context(), userCtx.UserID)
	if err != nil {
		sendError(w, "InternalError", "Failed to list sessions", http.StatusInternalServerError, nil)
		return
	}

	// Identify the current session from the request's bearer token (0 if the request
	// was authenticated by a PAT rather than a session).
	currentID := h.coreService.CurrentSessionID(r.Context(), extractBearerToken(r))

	out := make([]sessionResponse, 0, len(sessions))
	for _, s := range sessions {
		item := sessionResponse{
			ID:        s.ID,
			UserAgent: s.UserAgent,
			IPAddress: s.IPAddress,
			CreatedAt: s.CreatedAt.UTC().Format(time.RFC3339),
			Current:   s.ID == currentID,
		}
		if s.ExpiresAt != nil {
			v := s.ExpiresAt.UTC().Format(time.RFC3339)
			item.ExpiresAt = &v
		}
		if s.LastSeenAt != nil {
			v := s.LastSeenAt.UTC().Format(time.RFC3339)
			item.LastSeenAt = &v
		}
		out = append(out, item)
	}
	sendSuccess(w, out, "")
}

// RevokeSession handles DELETE /auth/sessions/{id} — end one of the caller's sessions.
func (h *AuthHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "BadRequest", "Invalid session ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.RevokeOwnSession(r.Context(), userCtx.UserID, uint(id)); err != nil {
		sendError(w, "NotFound", "Session not found", http.StatusNotFound, nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// PasswordReset handles POST /auth/password-reset.
// Always returns success to prevent email enumeration.
//
// This route is intentionally unauthenticated (anyone must be able to request a
// reset for their own account), which also makes it reachable by anyone for ANY
// target email — with no compensating auth barrier the way the admin-triggered
// resend flows have (users.write / roles.assign). checkResendThrottle
// (ADR-028, per-email 10/day + 60s min-interval, already serialized per-process
// via setupResendMu) is the primary abuse control, but as a defense-in-depth
// backstop specific to this unauthenticated entry point, an IP-based budget
// (ADR-040's existing cluster-wide, DB-backed limiter, reused here) caps how
// many reset requests — and therefore how many outbound emails — a single
// source can trigger, independent of which email(s) it targets (#249).
func (h *AuthHandler) PasswordReset(w http.ResponseWriter, r *http.Request) {
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	if h.coreService.IsPasswordResetRateLimited(r.Context(), ip) {
		sendError(w, "TooManyRequests", "Too many password reset requests. Try again later.", http.StatusTooManyRequests, nil)
		return
	}
	h.coreService.RecordPasswordResetAttempt(r.Context(), ip)

	var body passwordResetRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}

	_ = h.coreService.RequestPasswordReset(r.Context(), body.Email)
	sendSuccess(w, nil, "If that email is registered, a reset link has been sent")
}

// InitSystem handles POST /system/init.
//
// Bootstraps a Keyorix server in a single call:
//   - Creates the admin user
//   - Creates canonical RBAC roles and permissions (admin, viewer)
//   - Creates the default project ("default")
//   - Creates three default environments (development, staging, production)
//
// Idempotent: if the server is already initialised, returns 200 with the
// current state and already_initialized=true. Safe to call from automation,
// Helm post-install hooks, and Docker Compose healthcheck scripts.
func (h *AuthHandler) InitSystem(w http.ResponseWriter, r *http.Request) {
	var body initSystemRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}

	// The bootstrap token authorizes the first-admin claim. Accept it from a header
	// (preferred) or the request body so the CLI and automation can supply it.
	token := r.Header.Get("X-Keyorix-Bootstrap-Token")
	if token == "" {
		token = body.Token
	}
	result, err := h.coreService.BootstrapSystem(r.Context(), &core.BootstrapRequest{
		Username:    body.Username,
		Email:       body.Email,
		Password:    body.Password,
		DisplayName: body.DisplayName,
		Token:       token,
	})
	if err != nil {
		// A bad/missing token or a weak password is a client error, not a 500.
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "bootstrap token") || strings.Contains(err.Error(), i18n.T("ErrorValidation", nil)) {
			status = http.StatusForbidden
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}

	// On an already-initialized system this endpoint is reachable UNAUTHENTICATED (the
	// bootstrap token only gates the create path). Returning the admin's username/email
	// and the project/environment topology here would be a pre-auth identity/topology
	// oracle, so the idempotent response carries only the initialized flag.
	if result.AlreadyInitialized {
		sendSuccess(w, map[string]interface{}{"already_initialized": true}, "System already initialised")
		return
	}

	envNames := make([]string, 0, len(result.Environments))
	for _, e := range result.Environments {
		envNames = append(envNames, e.Name)
	}

	resp := map[string]interface{}{
		"already_initialized": result.AlreadyInitialized,
		"environments":        envNames,
	}
	if result.User != nil {
		resp["user"] = map[string]interface{}{
			"id":       result.User.ID,
			"username": result.User.Username,
			"email":    result.User.Email,
		}
	}
	if result.Project != nil {
		resp["project"] = result.Project.Name
	}

	sendSuccess(w, resp, "System initialised successfully")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// extractBearerToken returns the session token for this request, preferring the
// httpOnly session cookie over the legacy "Authorization: Bearer <token>" header
// if both are present — mirrors middleware.extractRequestToken's precedence
// exactly, so a request authenticated via cookie by the Authentication
// middleware resolves to the same token here (needed for cache invalidation,
// "current session" detection, etc., all of which act on the actual token, not
// on how it arrived).
func extractBearerToken(r *http.Request) string {
	if cookie, err := r.Cookie(middleware.SessionCookieName); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(parts) == 2 && parts[0] == "Bearer" {
		return parts[1]
	}
	return ""
}

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// loginRateLimiter tracks failed login attempts per IP.
var loginRateLimiter = struct {
	sync.Mutex
	attempts map[string][]time.Time
}{attempts: make(map[string][]time.Time)}

const (
	loginMaxAttempts = 10
	loginWindow      = 15 * time.Minute
)

// checkLoginRateLimit returns true if the IP has exceeded the login attempt limit.
func checkLoginRateLimit(ip string) bool {
	loginRateLimiter.Lock()
	defer loginRateLimiter.Unlock()

	now := time.Now()
	cutoff := now.Add(-loginWindow)

	var recent []time.Time
	for _, t := range loginRateLimiter.attempts[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	loginRateLimiter.attempts[ip] = recent

	return len(recent) >= loginMaxAttempts
}

// recordLoginAttempt records a failed login attempt for the IP.
func recordLoginAttempt(ip string) {
	loginRateLimiter.Lock()
	defer loginRateLimiter.Unlock()
	loginRateLimiter.attempts[ip] = append(loginRateLimiter.attempts[ip], time.Now())
}

// AuthHandler handles authentication HTTP requests.
type AuthHandler struct {
	coreService *core.KeyorixCore
}

// NewAuthHandler constructs an AuthHandler.
func NewAuthHandler(coreService *core.KeyorixCore) *AuthHandler {
	return &AuthHandler{coreService: coreService}
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
	if checkLoginRateLimit(ip) {
		sendError(w, "TooManyRequests", "Too many login attempts. Try again later.", http.StatusTooManyRequests, nil)
		return
	}

	var body loginRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	session, user, err := h.coreService.Login(r.Context(), &core.LoginRequest{
		Username:  body.Username,
		Password:  body.Password,
		UserAgent: r.Header.Get("User-Agent"),
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
				"mfa_required":      true,
				"mfa_challenge":     challenge,
				"totp_available":    user.MFAEnabled,
				"webauthn_available": user.WebAuthnEnabled,
			}, "MFA required")
			return
		}
		recordLoginAttempt(ip)
		go h.coreService.LogAuthFailure(context.Background(), body.Username, ip) // #nosec G118
		sendError(w, "Unauthorized", "Invalid credentials", http.StatusUnauthorized, nil)
		return
	}

	resp := h.buildLoginResponse(r.Context(), session, user)

	// Audit log + last-login stamp (both non-blocking)
	ip, ua := r.RemoteAddr, r.Header.Get("User-Agent")
	go h.coreService.LogAuthLogin(context.Background(), user.ID, user.Username, ip, ua) // #nosec G118
	go func() { _ = h.coreService.RecordLogin(context.Background(), user.ID) }()        // #nosec G118

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
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
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
	result, err := h.coreService.CompleteSetup(r.Context(), body.Token, body.Password, r.Header.Get("User-Agent"), ip)
	if err != nil {
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
	go h.coreService.LogAuthLogin(context.Background(), result.User.ID, result.User.Username, ip, r.Header.Get("User-Agent")) // #nosec G118
	go func() { _ = h.coreService.RecordLogin(context.Background(), result.User.ID) }()                                       // #nosec G118

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

	// Audit log (non-blocking)
	ip, ua := r.RemoteAddr, r.Header.Get("User-Agent")
	go h.coreService.LogAuthLogout(context.Background(), logoutUserID, logoutUsername, ip, ua) // #nosec G118

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
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	user, err := h.coreService.GetUser(r.Context(), userCtx.UserID)
	if err != nil {
		sendError(w, "NotFound", "User not found", http.StatusNotFound, nil)
		return
	}

	sendSuccess(w, userProfileMap(user, h.userIdentity(r, userCtx.UserID)), "")
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
type updateProfileRequestBody struct {
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
}

// UpdateProfile handles PUT /auth/profile — self-scoped display name + email update.
func (h *AuthHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body updateProfileRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	user, err := h.coreService.UpdateOwnProfile(r.Context(), userCtx.UserID, body.DisplayName, body.Email)
	if err != nil {
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
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body changePasswordRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
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
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
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
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
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
func (h *AuthHandler) PasswordReset(w http.ResponseWriter, r *http.Request) {
	var body passwordResetRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
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
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	result, err := h.coreService.BootstrapSystem(r.Context(), &core.BootstrapRequest{
		Username:    body.Username,
		Email:       body.Email,
		Password:    body.Password,
		DisplayName: body.DisplayName,
	})
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
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

	msg := "System initialised successfully"
	if result.AlreadyInitialized {
		msg = "System already initialised"
	}
	sendSuccess(w, resp, msg)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// extractBearerToken pulls the token from an "Authorization: Bearer <token>" header.
func extractBearerToken(r *http.Request) string {
	parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(parts) == 2 && parts[0] == "Bearer" {
		return parts[1]
	}
	return ""
}

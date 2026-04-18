package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

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
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at,omitempty"`
	UserID    uint   `json:"user_id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
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
	var body loginRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	session, user, err := h.coreService.Login(r.Context(), &core.LoginRequest{
		Username: body.Username,
		Password: body.Password,
	})
	if err != nil {
		sendError(w, "Unauthorized", "Invalid credentials", http.StatusUnauthorized, nil)
		return
	}

	resp := loginResponseBody{
		Token:    session.SessionToken,
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
	}
	if session.ExpiresAt != nil {
		resp.ExpiresAt = session.ExpiresAt.UTC().Format(time.RFC3339)
	}

	// Audit log (non-blocking)
	ip, ua := r.RemoteAddr, r.Header.Get("User-Agent")
	go h.coreService.LogAuthLogin(context.Background(), user.ID, user.Username, ip, ua)

	sendSuccess(w, resp, "Login successful")
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

	// Audit log (non-blocking)
	ip, ua := r.RemoteAddr, r.Header.Get("User-Agent")
	go h.coreService.LogAuthLogout(context.Background(), logoutUserID, logoutUsername, ip, ua)

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

	profile := map[string]interface{}{
		"id":           user.ID,
		"username":     user.Username,
		"email":        user.Email,
		"display_name": user.DisplayName,
		"is_active":    user.IsActive,
		"created_at":   user.CreatedAt,
	}

	sendSuccess(w, profile, "")
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
// Creates the first admin user; fails with 409 if users already exist.
func (h *AuthHandler) InitSystem(w http.ResponseWriter, r *http.Request) {
	var body initSystemRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	user, err := h.coreService.InitializeSystem(r.Context(), &core.CreateUserRequest{
		Username:    body.Username,
		Email:       body.Email,
		Password:    body.Password,
		DisplayName: body.DisplayName,
	})
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "already initialized") {
			status = http.StatusConflict
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}

	sendSuccess(w, map[string]interface{}{
		"id":           user.ID,
		"username":     user.Username,
		"email":        user.Email,
		"display_name": user.DisplayName,
	}, "System initialized successfully")
}

type seedRequestBody struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// SeedSystem handles POST /api/v1/system/seed.
// Creates the first admin user plus default namespace, zone, and environments.
// Returns 409 if the system has already been seeded.
func (h *AuthHandler) SeedSystem(w http.ResponseWriter, r *http.Request) {
	var body seedRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	result, err := h.coreService.SeedSystem(r.Context(), &core.SeedRequest{
		Username:    body.Username,
		Email:       body.Email,
		Password:    body.Password,
		DisplayName: body.DisplayName,
	})
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "already seeded") {
			status = http.StatusConflict
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}

	envNames := make([]string, 0, len(result.Environments))
	for _, e := range result.Environments {
		envNames = append(envNames, e.Name)
	}

	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, map[string]interface{}{
		"user":         map[string]interface{}{"id": result.User.ID, "username": result.User.Username, "email": result.User.Email},
		"namespace":    result.Namespace.Name,
		"zone":         result.Zone.Name,
		"environments": envNames,
	}, "System seeded successfully")
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

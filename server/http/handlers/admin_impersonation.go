// admin_impersonation.go — admin impersonation start/end endpoints.
//
// Start (POST /api/v1/admin/impersonate) is gated by the users.impersonate
// permission, which only global admins hold (admin-bypass). It issues a separate
// short-lived session for the target user and returns its token; the admin's own
// session is untouched so the client can swap back without re-authentication.
//
// End (POST /api/v1/auth/end-impersonation) is self-scoped: it terminates the
// impersonation session presented in the Authorization header and logs the
// bracketing impersonation.end event. See internal/core/impersonation.go.
package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ImpersonationHandler handles admin impersonation requests.
type ImpersonationHandler struct {
	coreService *core.KeyorixCore
}

// NewImpersonationHandler constructs an ImpersonationHandler.
func NewImpersonationHandler(coreService *core.KeyorixCore) *ImpersonationHandler {
	return &ImpersonationHandler{coreService: coreService}
}

type startImpersonationBody struct {
	UserID uint `json:"user_id"`
}

type impersonationResponse struct {
	Token          string `json:"token"`
	ExpiresAt      string `json:"expires_at,omitempty"`
	UserID         uint   `json:"user_id"`
	Username       string `json:"username"`
	DisplayName    string `json:"display_name"`
	ImpersonatedBy uint   `json:"impersonated_by"`
}

// Start handles POST /api/v1/admin/impersonate.
func (h *ImpersonationHandler) Start(w http.ResponseWriter, r *http.Request) {
	admin := middleware.GetUserFromContext(r.Context())
	if admin == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	// An impersonation session must not itself be used to start another one.
	if admin.ImpersonatedBy != nil {
		sendError(w, "Forbidden", "Cannot impersonate while impersonating", http.StatusForbidden, nil)
		return
	}

	var body startImpersonationBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if body.UserID == 0 {
		sendError(w, "BadRequest", "user_id is required", http.StatusBadRequest, nil)
		return
	}

	session, target, err := h.coreService.StartImpersonation(r.Context(), admin.UserID, body.UserID, clientIP(r))
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "yourself"):
			sendError(w, "BadRequest", "Cannot impersonate yourself", http.StatusBadRequest, nil)
		case strings.Contains(err.Error(), "not found"):
			sendError(w, "NotFound", "Target user not found", http.StatusNotFound, nil)
		default:
			sendError(w, "InternalError", "Failed to start impersonation", http.StatusInternalServerError, nil)
		}
		return
	}

	resp := impersonationResponse{
		Token:          session.SessionToken,
		UserID:         target.ID,
		Username:       target.Username,
		DisplayName:    target.DisplayName,
		ImpersonatedBy: admin.UserID,
	}
	if session.ExpiresAt != nil {
		resp.ExpiresAt = session.ExpiresAt.UTC().Format(time.RFC3339)
	}
	sendSuccess(w, resp, "Impersonation started")
}

// End handles POST /api/v1/auth/end-impersonation.
func (h *ImpersonationHandler) End(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		sendError(w, "BadRequest", "Missing authorization token", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.EndImpersonation(r.Context(), token); err != nil {
		if strings.Contains(err.Error(), "not an impersonation") {
			sendError(w, "BadRequest", "Not an impersonation session", http.StatusBadRequest, nil)
		} else {
			sendError(w, "InternalError", "Failed to end impersonation", http.StatusInternalServerError, nil)
		}
		return
	}
	// Evict the impersonation token from the auth cache immediately.
	middleware.InvalidateTokenCache(token)
	sendSuccess(w, nil, "Impersonation ended")
}

// clientIP strips the port from RemoteAddr for audit attribution.
func clientIP(r *http.Request) string {
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

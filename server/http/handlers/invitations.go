// invitations.go — project invitation + access-request endpoints (ADR-024).
//
// Invitations are admin-driven (roles.assign). Access requests are user-driven:
// requesting and withdrawing are self-service (any authenticated user — the
// whole point is the user does NOT yet have project access), while listing and
// approving/rejecting require roles.assign at the project scope.
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ── Invitations ────────────────────────────────────────────────────────────

// ListInvitations handles GET /api/v1/projects/{id}/invitations.
func (h *CatalogHandler) ListInvitations(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	invitations, err := h.coreService.ListProjectInvitations(r.Context(), uint(id))
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"invitations": invitations}, "")
}

// CreateInvitation handles POST /api/v1/projects/{id}/invitations.
func (h *CatalogHandler) CreateInvitation(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if body.Email == "" || body.Role == "" {
		sendError(w, "ValidationError", "email and role are required", http.StatusBadRequest, nil)
		return
	}
	inv, err := h.coreService.InviteToProject(r.Context(), uint(id), body.Email, body.Role, actor.UserID)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "unknown role") || strings.Contains(err.Error(), "required") {
			status = http.StatusBadRequest
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, map[string]interface{}{"invitation": inv}, "Invitation created")
}

// RevokeInvitation handles DELETE /api/v1/projects/{id}/invitations/{invitationId}.
func (h *CatalogHandler) RevokeInvitation(w http.ResponseWriter, r *http.Request) {
	invID, err := strconv.ParseUint(chi.URLParam(r, "invitationId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid invitation ID", http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	if err := h.coreService.RevokeInvitation(r.Context(), uint(invID), actor.UserID); err != nil {
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "not found"):
			status = http.StatusNotFound
		case strings.Contains(err.Error(), "only a pending"):
			status = http.StatusConflict
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	sendSuccess(w, nil, "Invitation revoked")
}

// ── Access requests ──────────────────────────────────────────────────────────

// ListAccessRequests handles GET /api/v1/projects/{id}/access-requests.
func (h *CatalogHandler) ListAccessRequests(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	requests, err := h.coreService.ListAccessRequests(r.Context(), uint(id))
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"access_requests": requests}, "")
}

// CreateAccessRequest handles POST /api/v1/projects/{id}/access-requests (self-service).
func (h *CatalogHandler) CreateAccessRequest(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		SuggestedRole string `json:"suggested_role"`
		Reason        string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	req, err := h.coreService.RequestProjectAccess(r.Context(), uint(id), actor.UserID, body.SuggestedRole, body.Reason)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "unknown role") || strings.Contains(err.Error(), "required") {
			status = http.StatusBadRequest
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, map[string]interface{}{"access_request": req}, "Access requested")
}

// ResolveAccessRequest handles PUT /api/v1/projects/{id}/access-requests/{requestId}
// for an admin: body {"action":"approve"|"reject", "granted_role":..., "reason":...}.
func (h *CatalogHandler) ResolveAccessRequest(w http.ResponseWriter, r *http.Request) {
	reqID, err := strconv.ParseUint(chi.URLParam(r, "requestId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid request ID", http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Action      string `json:"action"`
		GrantedRole string `json:"granted_role"`
		Reason      string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	var resolveErr error
	switch body.Action {
	case "approve":
		_, resolveErr = h.coreService.ApproveAccessRequest(r.Context(), uint(reqID), actor.UserID, body.GrantedRole)
	case "reject":
		_, resolveErr = h.coreService.RejectAccessRequest(r.Context(), uint(reqID), actor.UserID, body.Reason)
	default:
		sendError(w, "ValidationError", "action must be approve or reject", http.StatusBadRequest, nil)
		return
	}
	if resolveErr != nil {
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(resolveErr.Error(), "not found"):
			status = http.StatusNotFound
		case strings.Contains(resolveErr.Error(), "only a pending"), strings.Contains(resolveErr.Error(), "unknown role"), strings.Contains(resolveErr.Error(), "required"):
			status = http.StatusConflict
		}
		sendError(w, "Error", resolveErr.Error(), status, nil)
		return
	}
	sendSuccess(w, nil, "Access request "+body.Action+"d")
}

// WithdrawAccessRequest handles POST /api/v1/projects/{id}/access-requests/{requestId}/withdraw (self-service).
func (h *CatalogHandler) WithdrawAccessRequest(w http.ResponseWriter, r *http.Request) {
	reqID, err := strconv.ParseUint(chi.URLParam(r, "requestId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid request ID", http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	if err := h.coreService.WithdrawAccessRequest(r.Context(), uint(reqID), actor.UserID); err != nil {
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "not found"):
			status = http.StatusNotFound
		case strings.Contains(err.Error(), "not your"):
			status = http.StatusForbidden
		case strings.Contains(err.Error(), "only a pending"):
			status = http.StatusConflict
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	sendSuccess(w, nil, "Access request withdrawn")
}

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
	"github.com/keyorixhq/keyorix/internal/core"
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
	inv, prov, err := h.coreService.InviteToProjectWithLink(r.Context(), uint(id), body.Email, body.Role, actor.UserID)
	if err != nil {
		// A nil inv means the invitation was not created at all; a non-nil inv with an
		// error means it was created but the link could not be provisioned (e.g.
		// base_url unset) — surface that so the admin can fix config and resend.
		if inv == nil {
			status := http.StatusInternalServerError
			if strings.Contains(err.Error(), "unknown role") || strings.Contains(err.Error(), "required") {
				status = http.StatusBadRequest
			}
			sendError(w, "Error", err.Error(), status, nil)
			return
		}
		w.WriteHeader(http.StatusCreated)
		sendSuccess(w, map[string]interface{}{"invitation": inv, "delivery_error": err.Error()},
			"Invitation created but the setup link could not be delivered")
		return
	}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, map[string]interface{}{"invitation": inv, "setup_link": prov}, "Invitation created")
}

// CreateGlobalInvitation is the Global-Admin counterpart to CreateInvitation: a
// non-project-scoped invite (ADR-024) carrying an optional system role plus
// per-project assignments, all applied atomically when the user accepts. Gated by
// users.write (system scope) since it provisions an account-to-be with grants.
func (h *CatalogHandler) CreateGlobalInvitation(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Email              string `json:"email"`
		Role               string `json:"role"` // system role (optional; defaults to system_viewer)
		ProjectAssignments []struct {
			ProjectID uint   `json:"project_id"`
			Role      string `json:"role"`
		} `json:"project_assignments"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if body.Email == "" {
		sendError(w, "ValidationError", "email is required", http.StatusBadRequest, nil)
		return
	}
	assignments := make([]core.ProjectAssignment, 0, len(body.ProjectAssignments))
	for _, a := range body.ProjectAssignments {
		assignments = append(assignments, core.ProjectAssignment{ProjectID: a.ProjectID, Role: a.Role})
	}
	inv, prov, err := h.coreService.InviteGlobalWithLink(r.Context(), body.Email, body.Role, assignments, actor.UserID)
	if err != nil {
		// A nil inv means the invitation was not created at all (bad input); a non-nil
		// inv with an error means it exists but the link couldn't be provisioned (e.g.
		// base_url unset) — surface that so the admin can fix config and resend.
		if inv == nil {
			status := http.StatusInternalServerError
			if strings.Contains(err.Error(), "unknown") || strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "needs a") {
				status = http.StatusBadRequest
			}
			sendError(w, "Error", err.Error(), status, nil)
			return
		}
		w.WriteHeader(http.StatusCreated)
		sendSuccess(w, map[string]interface{}{"invitation": inv, "delivery_error": err.Error()},
			"Invitation created but the setup link could not be delivered")
		return
	}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, map[string]interface{}{"invitation": inv, "setup_link": prov}, "Invitation created")
}

// ResendInvitation handles POST /api/v1/projects/{id}/invitations/{invitationId}/resend
// (ADR-028): it reissues the invitation's accept link and re-delivers it.
func (h *CatalogHandler) ResendInvitation(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
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
	prov, err := h.coreService.ResendInvitationLink(r.Context(), uint(projectID), uint(invID), actor.UserID)
	if err != nil {
		msg := err.Error()
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(msg, "not found"):
			status = http.StatusNotFound
		case strings.Contains(msg, "only a pending"):
			status = http.StatusConflict
		case strings.Contains(msg, "limit") || strings.Contains(msg, "wait"):
			status = http.StatusTooManyRequests
		case strings.Contains(msg, "base_url"):
			status = http.StatusBadRequest
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"setup_link": prov}, "Invitation link resent")
}

// RevokeInvitation handles DELETE /api/v1/projects/{id}/invitations/{invitationId}.
func (h *CatalogHandler) RevokeInvitation(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
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
	if err := h.coreService.RevokeInvitation(r.Context(), uint(projectID), uint(invID), actor.UserID); err != nil {
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
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
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
		_, resolveErr = h.coreService.ApproveAccessRequest(r.Context(), uint(projectID), uint(reqID), actor.UserID, body.GrantedRole)
	case "reject":
		_, resolveErr = h.coreService.RejectAccessRequest(r.Context(), uint(projectID), uint(reqID), actor.UserID, body.Reason)
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

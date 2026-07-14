// invitations.go — project invitation + access-request endpoints (ADR-024).
//
// Invitations are admin-driven (roles.assign). Access requests are user-driven:
// requesting and withdrawing are self-service (any authenticated user — the
// whole point is the user does NOT yet have project access), while listing and
// approving/rejecting require roles.assign at the project scope.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)


// ── Invitations ────────────────────────────────────────────────────────────

// ListInvitations handles GET /api/v1/projects/{id}/invitations.
func (h *CatalogHandler) ListInvitations(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	invitations, err := h.coreService.ListProjectInvitations(r.Context(), uint(id))
	if err != nil {
		log.Printf("Error listing invitations for project %d: %v", id, err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"invitations": invitations}, "")
}

// CreateInvitation handles POST /api/v1/projects/{id}/invitations.
func (h *CatalogHandler) CreateInvitation(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", errInvalidRequestBody, http.StatusBadRequest, nil)
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
			msg := err.Error()
			if strings.Contains(msg, errUnknownRole) || strings.Contains(msg, "required") {
				status = http.StatusBadRequest
			} else {
				log.Printf("Error inviting %q to project %d: %v", body.Email, id, err)
				msg = clientSafe(err)
			}
			sendError(w, "Error", msg, status, nil)
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
func (h *CatalogHandler) CreateGlobalInvitation(w http.ResponseWriter, r *http.Request) { // NOSONAR -- cognitive complexity 20, suppress go:S3776
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
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
		sendError(w, "InvalidJSON", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	if body.Email == "" {
		sendError(w, "ValidationError", "email is required", http.StatusBadRequest, nil)
		return
	}
	// Privilege ceiling (mirrors CreateUser): the route gate proves users.write, but a
	// users.write holder must not be able to GRANT a role they themselves lack authority
	// to assign — otherwise an onboarding manager without roles.assign could invite an
	// account (their own email) as system_admin and own the install on accept. Require
	// roles.assign at the relevant scope for the system role and each project assignment.
	if body.Role != "" {
		if ok, aerr := h.coreService.AuthorizePrincipal(r.Context(), actor.ActorKind(), actor.PrincipalID(), "roles.assign", core.Scope{}); aerr != nil || !ok {
			sendError(w, "Forbidden", "You may not invite with a system role you cannot assign", http.StatusForbidden, nil)
			return
		}
	}
	for _, a := range body.ProjectAssignments {
		if ok, aerr := h.coreService.AuthorizePrincipal(r.Context(), actor.ActorKind(), actor.PrincipalID(), "roles.assign", core.Scope{ProjectID: a.ProjectID}); aerr != nil || !ok {
			sendError(w, "Forbidden", "You may not invite with roles in a project where you cannot assign roles", http.StatusForbidden, nil)
			return
		}
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
			msg := err.Error()
			if strings.Contains(msg, "unknown") || strings.Contains(msg, "required") || strings.Contains(msg, "needs a") {
				status = http.StatusBadRequest
			} else {
				log.Printf("Error creating global invitation for %q: %v", body.Email, err)
				msg = clientSafe(err)
			}
			sendError(w, "Error", msg, status, nil)
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
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	invID, err := strconv.ParseUint(chi.URLParam(r, "invitationId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid invitation ID", http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	prov, err := h.coreService.ResendInvitationLink(r.Context(), uint(projectID), uint(invID), actor.UserID)
	if err != nil {
		msg := err.Error()
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(msg, errNotFound):
			status = http.StatusNotFound
		case strings.Contains(msg, errOnlyPending):
			status = http.StatusConflict
		case strings.Contains(msg, "limit") || strings.Contains(msg, "wait"):
			status = http.StatusTooManyRequests
		case strings.Contains(msg, "base_url"):
			status = http.StatusBadRequest
		default:
			log.Printf("Error resending invitation %d for project %d: %v", invID, projectID, err)
			msg = clientSafe(err)
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
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	invID, err := strconv.ParseUint(chi.URLParam(r, "invitationId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid invitation ID", http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	if err := h.coreService.RevokeInvitation(r.Context(), uint(projectID), uint(invID), actor.UserID); err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, errNotFound):
			status = http.StatusNotFound
		case strings.Contains(msg, errOnlyPending):
			status = http.StatusConflict
		default:
			log.Printf("Error revoking invitation %d for project %d: %v", invID, projectID, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, nil, "Invitation revoked")
}

// ── Access requests ──────────────────────────────────────────────────────────

// ListAccessRequests handles GET /api/v1/projects/{id}/access-requests.
func (h *CatalogHandler) ListAccessRequests(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	requests, err := h.coreService.ListAccessRequests(r.Context(), uint(id))
	if err != nil {
		log.Printf("Error listing access requests for project %d: %v", id, err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"access_requests": requests}, "")
}

// CreateAccessRequest handles POST /api/v1/projects/{id}/access-requests (self-service).
func (h *CatalogHandler) CreateAccessRequest(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		SuggestedRole string `json:"suggested_role"`
		Reason        string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	req, err := h.coreService.RequestProjectAccess(r.Context(), uint(id), actor.UserID, body.SuggestedRole, body.Reason)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		if strings.Contains(msg, errUnknownRole) || strings.Contains(msg, "required") {
			status = http.StatusBadRequest
		} else {
			log.Printf("Error creating access request for project %d: %v", id, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
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
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	reqID, err := strconv.ParseUint(chi.URLParam(r, "requestId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid request ID", http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Action      string `json:"action"`
		GrantedRole string `json:"granted_role"`
		Reason      string `json:"reason"`
		// GrantTTL (optional) makes an approval time-bound (just-in-time access):
		// a Go duration string (e.g. "4h", "30m"). Empty/absent = permanent grant.
		GrantTTL string `json:"grant_ttl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	var resolveErr error
	switch body.Action {
	case "approve":
		var ttl time.Duration
		if body.GrantTTL != "" {
			ttl, err = time.ParseDuration(body.GrantTTL)
			if err != nil || ttl < 0 {
				sendError(w, "ValidationError", "grant_ttl must be a non-negative Go duration (e.g. 4h)", http.StatusBadRequest, nil)
				return
			}
		}
		_, resolveErr = h.coreService.ApproveAccessRequestWithExpiry(r.Context(), uint(projectID), uint(reqID), actor.UserID, body.GrantedRole, ttl)
	case "reject":
		_, resolveErr = h.coreService.RejectAccessRequest(r.Context(), uint(projectID), uint(reqID), actor.UserID, body.Reason)
	default:
		sendError(w, "ValidationError", "action must be approve or reject", http.StatusBadRequest, nil)
		return
	}
	if resolveErr != nil {
		status := http.StatusInternalServerError
		msg := resolveErr.Error()
		switch {
		case strings.Contains(msg, errNotFound):
			status = http.StatusNotFound
		case strings.Contains(msg, errOnlyPending), strings.Contains(msg, errUnknownRole), strings.Contains(msg, "required"):
			status = http.StatusConflict
		default:
			log.Printf("Error resolving access request %d for project %d: %v", reqID, projectID, resolveErr)
			msg = clientSafe(resolveErr)
		}
		sendError(w, "Error", msg, status, nil)
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
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	if err := h.coreService.WithdrawAccessRequest(r.Context(), uint(reqID), actor.UserID); err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, errNotFound):
			status = http.StatusNotFound
		case strings.Contains(msg, "not your"):
			status = http.StatusForbidden
		case strings.Contains(msg, errOnlyPending):
			status = http.StatusConflict
		default:
			log.Printf("Error withdrawing access request %d: %v", reqID, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, nil, "Access request withdrawn")
}

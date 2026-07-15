// project_memberships.go — project membership lifecycle endpoints (ADR-022).
//
// These drive the onboarding state machine (invited → identity_verified →
// provisioned → active, revoked terminal), separate from the role-grant
// endpoints in project_members.go. All are project-scoped and gated by
// roles.assign at the project scope (so a project_admin can run onboarding).
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


// staleInviteThreshold is when an unaccepted invite is surfaced as stale (ADR-022).
const staleInviteThreshold = 7 * 24 * time.Hour

// ListProjectMemberships handles GET /api/v1/projects/{id}/memberships.
// With ?stale=true it returns only invited memberships older than 7 days.
func (h *CatalogHandler) ListProjectMemberships(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	if r.URL.Query().Get("stale") == "true" {
		all, err := h.coreService.StaleInvites(r.Context(), staleInviteThreshold)
		if err != nil {
			log.Printf("Error listing stale invites: %v", err)
			sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
			return
		}
		// StaleInvites is install-wide; narrow to this project for the endpoint.
		stale := make([]interface{}, 0, len(all))
		for _, m := range all {
			if m.ProjectID == uint(id) {
				stale = append(stale, m)
			}
		}
		sendSuccess(w, map[string]interface{}{"memberships": stale}, "")
		return
	}
	memberships, err := h.coreService.ListProjectMemberships(r.Context(), uint(id))
	if err != nil {
		log.Printf("Error listing memberships for project %d: %v", id, err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"memberships": memberships}, "")
}

// InviteMember handles POST /api/v1/projects/{id}/memberships.
func (h *CatalogHandler) InviteMember(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		UserID      uint   `json:"user_id"`
		Role        string `json:"role"`
		IDPResolved bool   `json:"idp_resolved"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if body.UserID == 0 || body.Role == "" {
		sendError(w, "ValidationError", "user_id and role are required", http.StatusBadRequest, nil)
		return
	}
	m, err := h.coreService.InviteMember(r.Context(), uint(id), body.UserID, body.Role, actor.UserID, body.IDPResolved)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, "already has"):
			status = http.StatusConflict
		case strings.Contains(msg, "unknown role"), strings.Contains(msg, "required"):
			status = http.StatusBadRequest
		default:
			log.Printf("Error inviting member to project %d: %v", id, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, map[string]interface{}{"membership": m}, "Member invited")
}

// TransitionMembership handles PUT /api/v1/projects/{id}/memberships/{membershipId}.
// Body: {"action": "verify" | "provision" | "activate" | "revoke"}.
func (h *CatalogHandler) TransitionMembership(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	membershipID, err := strconv.ParseUint(chi.URLParam(r, "membershipId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid membership ID", http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	to, ok := membershipActionState(body.Action)
	if !ok {
		sendError(w, "ValidationError", "action must be verify, provision, activate, or revoke", http.StatusBadRequest, nil)
		return
	}
	m, err := h.coreService.TransitionMembership(r.Context(), uint(projectID), uint(membershipID), to, actor.UserID)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, "not found"):
			status = http.StatusNotFound
		case strings.Contains(msg, "cannot transition"):
			status = http.StatusConflict
		default:
			log.Printf("Error transitioning membership %d for project %d: %v", membershipID, projectID, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"membership": m}, "Membership updated")
}

// membershipActionState maps a request action verb to its target state.
func membershipActionState(action string) (string, bool) {
	switch action {
	case "verify":
		return core.MembershipIdentityVerified, true
	case "provision":
		return core.MembershipProvisioned, true
	case "activate":
		return core.MembershipActive, true
	case "revoke":
		return core.MembershipRevoked, true
	default:
		return "", false
	}
}

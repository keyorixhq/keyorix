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

// ListProjectMembers handles GET /api/v1/projects/{id}/members
func (h *CatalogHandler) ListProjectMembers(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	members, err := h.coreService.ListProjectMembers(r.Context(), uint(id))
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"members": members}, "")
}

// GetProjectAccessReview handles GET /api/v1/projects/{id}/access-review — the
// role-based access recertification report (ISO 27001 A.5.18): every project-scoped
// role grant whose role confers a secrets.* permission, with the highest action.
func (h *CatalogHandler) GetProjectAccessReview(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	entries, err := h.coreService.GenerateProjectAccessReview(r.Context(), uint(id))
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"entries": entries, "count": len(entries)}, "")
}

// accessReviewDecisionBody is the request body for a recertification decision on
// one access-review entry (revoke or attest). It mirrors the AccessReviewEntry the
// review returned, identifying the grant to act on.
type accessReviewDecisionBody struct {
	Source        string `json:"source"`
	PrincipalType string `json:"principal_type"`
	PrincipalID   uint   `json:"principal_id"`
	RoleID        uint   `json:"role_id"`
	EnvironmentID uint   `json:"environment_id"`
	SecretID      uint   `json:"secret_id"`
}

// decodeAccessReviewDecision parses the project ID, acting reviewer and decision
// body shared by the revoke and attest handlers. It writes the error response and
// returns ok=false on any failure.
func (h *CatalogHandler) decodeAccessReviewDecision(w http.ResponseWriter, r *http.Request) (uint, uint, core.AccessReviewDecision, bool) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return 0, 0, core.AccessReviewDecision{}, false
	}
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return 0, 0, core.AccessReviewDecision{}, false
	}
	var body accessReviewDecisionBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return 0, 0, core.AccessReviewDecision{}, false
	}
	if body.Source == "" {
		sendError(w, "ValidationError", "source is required", http.StatusBadRequest, nil)
		return 0, 0, core.AccessReviewDecision{}, false
	}
	return uint(id), userCtx.UserID, core.AccessReviewDecision{
		Source:        body.Source,
		PrincipalType: body.PrincipalType,
		PrincipalID:   body.PrincipalID,
		RoleID:        body.RoleID,
		EnvironmentID: body.EnvironmentID,
		SecretID:      body.SecretID,
	}, true
}

// RevokeProjectAccessReview handles POST /api/v1/projects/{id}/access-review/revoke
// — close the recertification loop by removing the grant identified in the body (a
// role assignment or a share). Gated by roles.assign at the project scope.
func (h *CatalogHandler) RevokeProjectAccessReview(w http.ResponseWriter, r *http.Request) {
	projectID, actorID, decision, ok := h.decodeAccessReviewDecision(w, r)
	if !ok {
		return
	}
	if err := h.coreService.RevokeAccessReviewGrant(r.Context(), actorID, projectID, decision); err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, "required") || strings.Contains(msg, "unknown access-review source") || strings.Contains(msg, "ownership cannot be revoked"):
			status = http.StatusBadRequest
		case strings.Contains(msg, "no matching share") || strings.Contains(msg, "not found"):
			status = http.StatusNotFound
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, nil, "Access revoked")
}

// AttestProjectAccessReview handles POST /api/v1/projects/{id}/access-review/attest
// — certify the grant in the body was reviewed and kept (audit-only, the evidence
// of recertification). Gated by roles.read at the project scope.
func (h *CatalogHandler) AttestProjectAccessReview(w http.ResponseWriter, r *http.Request) {
	projectID, actorID, decision, ok := h.decodeAccessReviewDecision(w, r)
	if !ok {
		return
	}
	if err := h.coreService.AttestAccessReviewGrant(r.Context(), actorID, projectID, decision); err != nil {
		sendError(w, "Error", err.Error(), http.StatusBadRequest, nil)
		return
	}
	sendSuccess(w, nil, "Access attested")
}

// AddProjectMember handles POST /api/v1/projects/{id}/members
func (h *CatalogHandler) AddProjectMember(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	var body struct {
		UserID uint   `json:"user_id"`
		Role   string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if body.UserID == 0 || body.Role == "" {
		sendError(w, "ValidationError", "user_id and role are required", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.AddProjectMember(r.Context(), userCtx.UserID, uint(id), body.UserID, body.Role); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "already") {
			status = http.StatusConflict
		} else if strings.Contains(err.Error(), "unknown role") {
			status = http.StatusBadRequest
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, nil, "Member added")
}

// UpdateProjectMember handles PUT /api/v1/projects/{id}/members/{userId}
func (h *CatalogHandler) UpdateProjectMember(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	userID, err := strconv.ParseUint(chi.URLParam(r, "userId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}
	var body struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if body.Role == "" {
		sendError(w, "ValidationError", "role is required", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.SetProjectMemberRole(r.Context(), userCtx.UserID, uint(id), uint(userID), body.Role); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "unknown role") {
			status = http.StatusBadRequest
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	sendSuccess(w, nil, "Member role updated")
}

// RemoveProjectMember handles DELETE /api/v1/projects/{id}/members/{userId}
func (h *CatalogHandler) RemoveProjectMember(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	userID, err := strconv.ParseUint(chi.URLParam(r, "userId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid user ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.RemoveProjectMember(r.Context(), uint(id), uint(userID)); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not a member") {
			status = http.StatusNotFound
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	sendSuccess(w, nil, "Member removed")
}

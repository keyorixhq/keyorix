// secret_acl_handler.go — per-secret ACL handlers (RBAC Phase 3).
//
// Routes (under /api/v1/secrets/{id}/acl):
//
//	GET    /{id}/acl           — list ACL grants; requires secrets.manage
//	POST   /{id}/acl           — grant; body {user_id, permissions}; requires secrets.manage
//	DELETE /{id}/acl/{aclId}  — revoke; requires secrets.manage
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ListSecretACLs handles GET /api/v1/secrets/{id}/acl
func (h *SecretHandler) ListSecretACLs(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	secretID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}
	acls, err := h.coreService.ListSecretACLs(r.Context(), uint(secretID))
	if err != nil {
		h.sendError(w, "Error", err.Error(), aclErrorStatus(err.Error()), nil)
		return
	}
	h.sendSuccess(w, acls, "")
}

// GrantSecretACL handles POST /api/v1/secrets/{id}/acl
func (h *SecretHandler) GrantSecretACL(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	secretID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}
	var body struct {
		UserID      uint     `json:"user_id"`
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if body.UserID == 0 {
		h.sendError(w, "InvalidParameter", "user_id is required", http.StatusBadRequest, nil)
		return
	}
	if len(body.Permissions) == 0 {
		h.sendError(w, "InvalidParameter", "permissions is required and must not be empty", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.GrantSecretACL(r.Context(), userCtx.UserID, uint(secretID), body.UserID, body.Permissions); err != nil {
		h.sendError(w, "Error", err.Error(), aclErrorStatus(err.Error()), nil)
		return
	}
	h.sendSuccess(w, map[string]bool{"granted": true}, "ACL granted")
}

// RevokeSecretACL handles DELETE /api/v1/secrets/{id}/acl/{aclId}
func (h *SecretHandler) RevokeSecretACL(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	secretID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}
	aclID, err := strconv.ParseUint(chi.URLParam(r, "aclId"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid ACL ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.RevokeSecretACL(r.Context(), userCtx.UserID, uint(secretID), uint(aclID)); err != nil {
		h.sendError(w, "Error", err.Error(), aclErrorStatus(err.Error()), nil)
		return
	}
	h.sendSuccess(w, map[string]bool{"revoked": true}, "ACL revoked")
}

// aclErrorStatus maps a core ACL error to an HTTP status.
func aclErrorStatus(msg string) int {
	switch {
	case strings.Contains(msg, "not found"):
		return http.StatusNotFound
	case strings.Contains(msg, "invalid"), strings.Contains(msg, "required"), strings.Contains(msg, "permission"):
		return http.StatusBadRequest
	case strings.Contains(msg, "not authorized"):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

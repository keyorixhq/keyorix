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
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// secretACLResponse is the wire shape for a SecretACL grant, distinct from
// models.SecretACL: that model stores Permissions as a JSON-encoded string
// column (see its own doc comment), but openapi.yaml's SecretACL schema
// declares permissions as a real JSON array. Marshaling the model directly
// would emit permissions as an escaped string instead of an array, failing
// schema validation -- caught by the contract-test harness's exercising
// test for listSecretACLs once it validated a populated response instead of
// only ever asserting against an empty list.
type secretACLResponse struct {
	ID          uint      `json:"id"`
	SecretID    uint      `json:"secret_id"`
	UserID      uint      `json:"user_id"`
	Permissions []string  `json:"permissions"`
	GrantedBy   uint      `json:"granted_by"`
	CreatedAt   time.Time `json:"created_at"`
}

func toSecretACLResponse(acls []*models.SecretACL) []secretACLResponse {
	out := make([]secretACLResponse, len(acls))
	for i, a := range acls {
		out[i] = secretACLResponse{
			ID:          a.ID,
			SecretID:    a.SecretID,
			UserID:      a.UserID,
			Permissions: core.DecodeSecretACLPerms(a.Permissions),
			GrantedBy:   a.GrantedBy,
			CreatedAt:   a.CreatedAt,
		}
	}
	return out
}

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
		status := aclErrorStatus(err.Error())
		msg := err.Error()
		if status == http.StatusInternalServerError {
			log.Printf("Error listing ACLs for secret %d: %v", secretID, err)
			msg = clientSafe(err)
		}
		h.sendError(w, "Error", msg, status, nil)
		return
	}
	h.sendSuccess(w, toSecretACLResponse(acls), "")
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
		status := aclErrorStatus(err.Error())
		msg := err.Error()
		if status == http.StatusInternalServerError {
			log.Printf("Error granting ACL for secret %d: %v", secretID, err)
			msg = clientSafe(err)
		}
		h.sendError(w, "Error", msg, status, nil)
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
		status := aclErrorStatus(err.Error())
		msg := err.Error()
		if status == http.StatusInternalServerError {
			log.Printf("Error revoking ACL %d for secret %d: %v", aclID, secretID, err)
			msg = clientSafe(err)
		}
		h.sendError(w, "Error", msg, status, nil)
		return
	}
	h.sendSuccess(w, map[string]bool{"revoked": true}, "ACL revoked")
}

// aclErrorStatus maps a core ACL error to an HTTP status.
//
// The "Validation error" case matches core.KeyorixCore's i18n.T("ErrorValidation", nil)
// prefix (see internal/i18n/locales/en.json), which every input-validation error in
// internal/core/secret_acl.go is built from (fmt.Errorf("%s: ...", i18n.T("ErrorValidation", nil), ...)).
// Some of those messages already happen to contain "invalid", "required", or
// "permission" and matched the case below before this one existed, but others
// (e.g. GrantSecretACL's "user %d is not a member of this secret's project" check)
// don't contain any of those substrings and fell through to the 500 default —
// misreporting a client-correctable 400-class request as an internal server error.
// Matching the shared "Validation error" prefix directly covers the whole class
// instead of enumerating every message body.
func aclErrorStatus(msg string) int {
	switch {
	case strings.Contains(msg, "not found"):
		return http.StatusNotFound
	case strings.Contains(msg, "Validation error"), strings.Contains(msg, "invalid"), strings.Contains(msg, "required"), strings.Contains(msg, "permission"):
		return http.StatusBadRequest
	case strings.Contains(msg, "not authorized"):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

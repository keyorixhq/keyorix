// secrets_versions.go — GetSecretVersions and RotateSecret handlers.
//
// Handles secret versioning and rotation.
// For CRUD see secrets_crud.go. For listing see secrets_list.go.
package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// GetSecretVersions handles GET /api/v1/secrets/{id}/versions
func (h *SecretHandler) GetSecretVersions(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}

	versions, err := h.coreService.GetSecretVersionsWithPermissionCheck(r.Context(), uint(id), userCtx.UserID)
	if err != nil {
		log.Printf("Error getting secret versions: %v", err)
		if strings.Contains(err.Error(), errNotFound) {
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		} else if strings.Contains(err.Error(), "permission denied") {
			h.sendError(w, "Forbidden", "Access denied", http.StatusForbidden, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to get secret versions", http.StatusInternalServerError, nil)
		}
		return
	}

	// Log as a secret read — fetching versions means the caller is accessing the secret value.
	secret, sErr := h.coreService.GetSecret(r.Context(), uint(id))
	if sErr == nil && secret != nil {
		ip, ua := r.RemoteAddr, r.Header.Get("User-Agent")
		auditCtx := core.DetachedAuditContext(r.Context())
		goSafe(func() {
			h.coreService.LogSecretReadWithProject(auditCtx, userCtx.UserID, uint(id), secret.ProjectID, userCtx.Username, secret.Name, ip, ua)
		}) // #nosec G118
	}

	h.sendSuccess(w, map[string]any{"versions": versions}, "")
}

// RotateSecret handles POST /api/v1/secrets/{id}/rotate
func (h *SecretHandler) RotateSecret(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "BadRequest", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}

	var reqBody struct {
		// The `validate:"required"` tag here is decorative: this handler never
		// calls h.validator.Validate, relying instead on the manual == ""
		// check below. Harmless today (the manual check covers the same
		// case), but the tag would silently fail to protect a future rule
		// added to the tag without a matching manual check (see #347).
		NewValue string `json:"new_value" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if reqBody.NewValue == "" {
		h.sendError(w, "ValidationError", "new_value is required", http.StatusBadRequest, nil)
		return
	}

	// RotateSecretOnDemand (#193): for a backend-bound secret this rotates the upstream
	// credential too (the same machinery the auto-rotation scheduler uses) rather than
	// just overwriting the stored value — never report success while the real,
	// potentially compromised credential is still live untouched upstream.
	secret, err := h.coreService.RotateSecretOnDemand(r.Context(), uint(id), []byte(reqBody.NewValue), userCtx.Username)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), errNotFound):
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		case strings.Contains(err.Error(), "backend"):
			// The upstream rotation failed or only partially completed — surfaced
			// distinctly (502) so the caller never mistakes this for a clean success,
			// even though a partial attempt may have stored a new value; see the audit
			// trail (secret.rotate_failed / secret.rotate_incomplete) for the outcome.
			log.Printf("rotation backend error for secret %d: %v", uint(id), err)
			h.sendError(w, "BackendRotationFailed", "Rotation backend call failed; see server logs for details", http.StatusBadGateway, nil)
		case strings.Contains(err.Error(), i18n.T("ErrorValidation", nil)):
			h.sendError(w, "ValidationError", err.Error(), http.StatusBadRequest, nil)
		default:
			h.sendError(w, "InternalError", "Failed to rotate secret", http.StatusInternalServerError, nil)
		}
		return
	}

	// Audit the rotation (async, detached) so the rotation inspector and the
	// activity feed have an attributable secret.rotated event.
	ip, ua := r.RemoteAddr, r.Header.Get("User-Agent")
	auditCtx := core.DetachedAuditContext(r.Context())
	goSafe(func() {
		h.coreService.LogSecretRotatedWithProject(auditCtx, userCtx.UserID, uint(id), secret.ProjectID, userCtx.Username, secret.Name, ip, ua)
	}) // #nosec G118

	h.sendSuccess(w, secret, "Secret rotated successfully")
}

// RollbackSecret handles POST /api/v1/secrets/{id}/rollback — restores the secret to a
// prior version's value as a new version. Scoped secrets.write (route-gated).
func (h *SecretHandler) RollbackSecret(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "BadRequest", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}
	var reqBody struct {
		// The `validate:"required"` tag here is decorative: this handler never
		// calls h.validator.Validate, relying instead on the manual <= 0
		// check below. See the same note on RotateSecret's NewValue above.
		Version int `json:"version" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if reqBody.Version <= 0 {
		h.sendError(w, "ValidationError", "version must be a positive version number", http.StatusBadRequest, nil)
		return
	}
	secret, err := h.coreService.RollbackSecret(r.Context(), uint(id), reqBody.Version, userCtx.UserID, userCtx.Username)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), errNotFound):
			h.sendError(w, "NotFound", err.Error(), http.StatusNotFound, nil)
		case strings.Contains(err.Error(), "already the current version"), strings.Contains(err.Error(), "version number must be positive"):
			h.sendError(w, "ValidationError", err.Error(), http.StatusBadRequest, nil)
		default:
			h.sendError(w, "InternalError", "Failed to roll back secret", http.StatusInternalServerError, nil)
		}
		return
	}
	h.sendSuccess(w, secret, fmt.Sprintf("Secret rolled back to version %d", reqBody.Version))
}

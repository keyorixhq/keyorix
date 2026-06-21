// secrets_crud.go — CreateSecret, GetSecret, UpdateSecret, DeleteSecret handlers.
//
// Handles the core CRUD lifecycle for secrets.
// For list/filter see secrets_list.go. For versioning see secrets_versions.go.
package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// CreateSecret handles POST /api/v1/secrets
func (h *SecretHandler) CreateSecret(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	var reqBody struct {
		Name           string            `json:"name" validate:"required,min=1,max=255"`
		Value          string            `json:"value" validate:"required"`
		ProjectID      uint              `json:"project_id"`
		EnvironmentID  uint              `json:"environment_id" validate:"required"`
		Type           string            `json:"type" validate:"required"`
		MaxReads       *int              `json:"max_reads,omitempty" validate:"omitempty,min=1"`
		Metadata       map[string]string `json:"metadata,omitempty"`
		Tags           []string          `json:"tags,omitempty"`
		Classification string            `json:"classification,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&reqBody); err != nil {
		h.sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	// Authorize against the target project/environment from the body — the
	// create route carries no path scope for the middleware to resolve.
	scope := core.Scope{ProjectID: reqBody.ProjectID, EnvironmentID: reqBody.EnvironmentID}
	if allowed, err := h.coreService.AuthorizePrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), "secrets.write", scope); err != nil || !allowed {
		h.sendError(w, "Forbidden", "Insufficient permissions", http.StatusForbidden, nil)
		return
	}
	// Per-project MFA policy (ADR-037): create carries no path scope for the
	// scoped-permission middleware, so enforce it here too (same as the other
	// in-handler-authorized mutations).
	if middleware.ProjectMFABlocked(r, h.coreService, scope.ProjectID) {
		middleware.WriteProjectMFARequired(w)
		return
	}

	req := &core.CreateSecretRequest{
		Name:           reqBody.Name,
		Value:          []byte(reqBody.Value),
		ProjectID:      reqBody.ProjectID,
		EnvironmentID:  reqBody.EnvironmentID,
		Type:           reqBody.Type,
		MaxReads:       reqBody.MaxReads,
		Metadata:       reqBody.Metadata,
		Tags:           reqBody.Tags,
		Classification: reqBody.Classification,
		CreatedBy:      userCtx.Username,
		OwnerID:        userCtx.UserID,
	}

	response, err := h.coreService.CreateSecret(r.Context(), req)
	if err != nil {
		log.Printf("Error creating secret: %v", err)
		if strings.Contains(err.Error(), "already exists") {
			h.sendError(w, "ConflictError", "Secret with this name already exists", http.StatusConflict, nil)
		} else if strings.Contains(err.Error(), "does not belong to project") || strings.Contains(err.Error(), "environment") && strings.Contains(err.Error(), "not found") {
			h.sendError(w, "ValidationError", err.Error(), http.StatusUnprocessableEntity, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to create secret", http.StatusInternalServerError, nil)
		}
		return
	}

	uid, sID, uname, sname := userCtx.UserID, response.ID, userCtx.Username, response.Name
	ip, ua := r.RemoteAddr, r.Header.Get("User-Agent")
	go h.coreService.LogSecretCreatedWithProject(core.DetachedAuditContext(r.Context()), uid, sID, response.ProjectID, uname, sname, ip, ua) // #nosec G118

	w.WriteHeader(http.StatusCreated)
	h.sendSuccess(w, response, i18n.T("SuccessSecretCreated", nil))
}

// ClassifySecret handles PATCH /api/v1/secrets/{id}/classification — set or clear
// the data-classification label (A.5.12). Gated by secrets.write at the secret's
// scope (via the route middleware).
func (h *SecretHandler) ClassifySecret(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}
	var reqBody struct {
		Classification string `json:"classification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	secret, err := h.coreService.ClassifySecret(r.Context(), userCtx.UserID, userCtx.Username, uint(id), reqBody.Classification)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, "classification must be"):
			status = http.StatusBadRequest
		case strings.Contains(msg, "not found"):
			status = http.StatusNotFound
		}
		h.sendError(w, "Error", msg, status, nil)
		return
	}
	h.sendSuccess(w, secret, "Classification updated")
}

// SetAutoRotate handles PATCH /api/v1/secrets/{id}/auto-rotate — toggles automated
// rotation (ADR-046) for a secret. Enable only for secrets whose value Keyorix owns.
func (h *SecretHandler) SetAutoRotate(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}
	var reqBody struct {
		Enabled bool   `json:"enabled"`
		Length  int    `json:"length"`  // 0 = default
		Charset string `json:"charset"` // "" = default alphanumeric
		Backend string `json:"backend"` // "" = regenerate in Keyorix only
		Ref     string `json:"ref"`     // upstream identifier (required iff backend set)
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.SetSecretAutoRotate(r.Context(), uint(id), core.AutoRotateSpec{
		Enabled: reqBody.Enabled, Length: reqBody.Length, Charset: reqBody.Charset,
		Backend: reqBody.Backend, Ref: reqBody.Ref,
	}, userCtx.UserID); err != nil {
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "not found"):
			status = http.StatusNotFound
		case strings.Contains(err.Error(), "unknown rotation charset"),
			strings.Contains(err.Error(), "out of range"),
			strings.Contains(err.Error(), "must be set together"),
			strings.Contains(err.Error(), "unknown rotation backend"),
			strings.Contains(err.Error(), "no rotation backends"):
			status = http.StatusBadRequest
		}
		h.sendError(w, "Error", err.Error(), status, nil)
		return
	}
	h.sendSuccess(w, map[string]interface{}{
		"id": id, "auto_rotate": reqBody.Enabled, "length": reqBody.Length,
		"charset": reqBody.Charset, "backend": reqBody.Backend, "ref": reqBody.Ref,
	}, "Auto-rotation updated")
}

// GetSecret handles GET /api/v1/secrets/{id}
func (h *SecretHandler) GetSecret(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}

	// Machine principals (ADR-030) are already authorized at the secret's scope
	// by the route's scoped-permission gate; the per-user owner/sharing check
	// (and its user-id requirement) does not apply to them, so fetch directly.
	isMachine := userCtx.MachineIdentityID != nil

	var secret *models.SecretNode
	if isMachine {
		secret, err = h.coreService.GetSecret(r.Context(), uint(id))
	} else {
		secret, err = h.coreService.GetSecretWithPermissionCheck(r.Context(), uint(id), userCtx.UserID)
	}
	if err != nil {
		log.Printf("Error getting secret: %v", err)
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		} else if strings.Contains(err.Error(), "permission denied") {
			h.sendError(w, "Forbidden", "Access denied", http.StatusForbidden, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to get secret", http.StatusInternalServerError, nil)
		}
		return
	}

	var response interface{} = secret
	if r.URL.Query().Get("include_value") == "true" { //nolint:goconst
		var value []byte
		if isMachine {
			value, err = h.coreService.GetSecretValue(r.Context(), uint(id))
		} else {
			value, err = h.coreService.GetSecretValueWithPermissionCheck(r.Context(), uint(id), userCtx.UserID)
		}
		if err != nil {
			log.Printf("Error getting secret value: %v", err)
			if strings.Contains(err.Error(), "permission denied") {
				h.sendError(w, "Forbidden", "Access denied", http.StatusForbidden, nil)
			} else {
				h.sendError(w, "InternalError", "Failed to get secret value", http.StatusInternalServerError, nil)
			}
			return
		}
		response = map[string]interface{}{"secret": secret, "value": string(value)}
	}

	uid, sID, uname, sname := userCtx.UserID, uint(id), userCtx.Username, secret.Name
	ip, ua := r.RemoteAddr, r.Header.Get("User-Agent")
	go h.coreService.LogSecretReadWithProject(core.DetachedAuditContext(r.Context()), uid, sID, secret.ProjectID, uname, sname, ip, ua) // #nosec G118

	h.sendSuccess(w, response, "")
}

// RestoreSecret handles POST /api/v1/secrets/{id}/restore — clears a
// soft-deleted secret's deleted_at (ADR-033). Authorized by the route's scoped
// secrets.write gate at the secret's own project/environment.
func (h *SecretHandler) RestoreSecret(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.RestoreSecret(r.Context(), userCtx.UserID, uint(id)); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		h.sendError(w, "Error", err.Error(), status, nil)
		return
	}
	h.sendSuccess(w, map[string]interface{}{"id": id, "restored": true}, "Secret restored")
}

// UpdateSecret handles PUT /api/v1/secrets/{id}
func (h *SecretHandler) UpdateSecret(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}

	var reqBody struct {
		Value    string `json:"value,omitempty"`
		MaxReads *int   `json:"max_reads,omitempty" validate:"omitempty,min=1"`
		// Expiration sets a new expiry (RFC3339); ClearExpiration removes an existing
		// one. They are mutually exclusive.
		Expiration      string `json:"expiration,omitempty"`
		ClearExpiration bool   `json:"clear_expiration,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&reqBody); err != nil {
		h.sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}
	if reqBody.Expiration != "" && reqBody.ClearExpiration {
		h.sendError(w, "ValidationError", "expiration and clear_expiration are mutually exclusive", http.StatusBadRequest, nil)
		return
	}

	req := &core.UpdateSecretRequest{
		ID:              uint(id),
		MaxReads:        reqBody.MaxReads,
		ClearExpiration: reqBody.ClearExpiration,
		UpdatedBy:       userCtx.Username,
		UserID:          userCtx.UserID,
	}
	if reqBody.Value != "" {
		req.Value = []byte(reqBody.Value)
	}
	if reqBody.Expiration != "" {
		exp, perr := time.Parse(time.RFC3339, reqBody.Expiration)
		if perr != nil {
			h.sendError(w, "ValidationError", "invalid expiration (use RFC3339)", http.StatusBadRequest, nil)
			return
		}
		req.Expiration = &exp
	}

	// Capture pre-update metadata for the audit diff (raw fetch, no read-count
	// side effect). Best-effort: a miss just yields an empty diff.
	oldSecret, _ := h.coreService.Storage().GetSecret(r.Context(), uint(id))

	response, err := h.coreService.UpdateSecretWithPermissionCheck(r.Context(), req)
	if err != nil {
		log.Printf("Error updating secret: %v", err)
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		} else if strings.Contains(err.Error(), "permission denied") {
			h.sendError(w, "Forbidden", "Access denied", http.StatusForbidden, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to update secret", http.StatusInternalServerError, nil)
		}
		return
	}

	uid, sID, uname, sname := userCtx.UserID, uint(id), userCtx.Username, response.Name
	ip, ua := r.RemoteAddr, r.Header.Get("User-Agent")
	diff := core.BuildSecretUpdateDiff(oldSecret, req, reqBody.Value != "")
	go h.coreService.LogSecretUpdatedWithDiff(core.DetachedAuditContext(r.Context()), uid, sID, response.ProjectID, uname, sname, ip, ua, diff) // #nosec G118

	h.sendSuccess(w, response, i18n.T("SuccessSecretUpdated", nil))
}

// DeleteSecret handles DELETE /api/v1/secrets/{id}
func (h *SecretHandler) DeleteSecret(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}

	// Pre-fetch name and project for audit log before the record is deleted.
	secretName := fmt.Sprintf("id=%d", id)
	var secretProjectID uint
	if s, err := h.coreService.GetSecretWithPermissionCheck(r.Context(), uint(id), userCtx.UserID); err == nil {
		secretName = s.Name
		secretProjectID = s.ProjectID
	}

	if err := h.coreService.DeleteSecretWithPermissionCheck(r.Context(), uint(id), userCtx.UserID); err != nil {
		log.Printf("Error deleting secret: %v", err)
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		} else if strings.Contains(err.Error(), "permission denied") {
			h.sendError(w, "Forbidden", "Access denied", http.StatusForbidden, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to delete secret", http.StatusInternalServerError, nil)
		}
		return
	}

	uid, sID, uname := userCtx.UserID, uint(id), userCtx.Username
	ip, ua := r.RemoteAddr, r.Header.Get("User-Agent")
	go h.coreService.LogSecretDeletedWithProject(core.DetachedAuditContext(r.Context()), uid, sID, secretProjectID, uname, secretName, ip, ua) // #nosec G118

	w.WriteHeader(http.StatusNoContent)
}

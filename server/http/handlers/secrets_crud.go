// secrets_crud.go — CreateSecret, GetSecret, UpdateSecret, DeleteSecret handlers.
//
// Handles the core CRUD lifecycle for secrets.
// For list/filter see secrets_list.go. For versioning see secrets_versions.go.
package handlers

import (
	"context"
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

// CreateSecret handles POST /api/v1/secrets
func (h *SecretHandler) CreateSecret(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	var reqBody struct {
		Name          string            `json:"name" validate:"required,min=1,max=255"`
		Value         string            `json:"value" validate:"required"`
		NamespaceID   uint              `json:"namespace_id" validate:"required"`
		ZoneID        uint              `json:"zone_id" validate:"required"`
		EnvironmentID uint              `json:"environment_id" validate:"required"`
		Type          string            `json:"type" validate:"required"`
		MaxReads      *int              `json:"max_reads,omitempty" validate:"omitempty,min=1"`
		Metadata      map[string]string `json:"metadata,omitempty"`
		Tags          []string          `json:"tags,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&reqBody); err != nil {
		h.sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	req := &core.CreateSecretRequest{
		Name:          reqBody.Name,
		Value:         []byte(reqBody.Value),
		NamespaceID:   reqBody.NamespaceID,
		ZoneID:        reqBody.ZoneID,
		EnvironmentID: reqBody.EnvironmentID,
		Type:          reqBody.Type,
		MaxReads:      reqBody.MaxReads,
		Metadata:      reqBody.Metadata,
		Tags:          reqBody.Tags,
		CreatedBy:     userCtx.Username,
		OwnerID:       userCtx.UserID,
	}

	response, err := h.coreService.CreateSecret(r.Context(), req)
	if err != nil {
		log.Printf("Error creating secret: %v", err)
		if strings.Contains(err.Error(), "already exists") {
			h.sendError(w, "ConflictError", "Secret with this name already exists", http.StatusConflict, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to create secret", http.StatusInternalServerError, nil)
		}
		return
	}

	uid, sID, uname, sname := userCtx.UserID, response.ID, userCtx.Username, response.Name
	ip, ua := r.RemoteAddr, r.Header.Get("User-Agent")
	go h.coreService.LogSecretCreated(context.Background(), uid, sID, uname, sname, ip, ua) // #nosec G118

	w.WriteHeader(http.StatusCreated)
	h.sendSuccess(w, response, i18n.T("SuccessSecretCreated", nil))
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

	secret, err := h.coreService.GetSecretWithPermissionCheck(r.Context(), uint(id), userCtx.UserID)
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
	if r.URL.Query().Get("include_value") == "true" {
		value, err := h.coreService.GetSecretValueWithPermissionCheck(r.Context(), uint(id), userCtx.UserID)
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
	go h.coreService.LogSecretRead(context.Background(), uid, sID, uname, sname, ip, ua) // #nosec G118

	h.sendSuccess(w, response, "")
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
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&reqBody); err != nil {
		h.sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	req := &core.UpdateSecretRequest{
		ID:        uint(id),
		MaxReads:  reqBody.MaxReads,
		UpdatedBy: userCtx.Username,
		UserID:    userCtx.UserID,
	}
	if reqBody.Value != "" {
		req.Value = []byte(reqBody.Value)
	}

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
	go h.coreService.LogSecretUpdated(context.Background(), uid, sID, uname, sname, ip, ua) // #nosec G118

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

	// Pre-fetch name for audit log before the record is deleted.
	secretName := fmt.Sprintf("id=%d", id)
	if s, err := h.coreService.GetSecretWithPermissionCheck(r.Context(), uint(id), userCtx.UserID); err == nil {
		secretName = s.Name
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
	go h.coreService.LogSecretDeleted(context.Background(), uid, sID, uname, secretName, ip, ua) // #nosec G118

	w.WriteHeader(http.StatusNoContent)
}

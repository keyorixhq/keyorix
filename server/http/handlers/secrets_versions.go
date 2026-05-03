// secrets_versions.go — GetSecretVersions and RotateSecret handlers.
//
// Handles secret versioning and rotation.
// For CRUD see secrets_crud.go. For listing see secrets_list.go.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// GetSecretVersions handles GET /api/v1/secrets/{id}/versions
func (h *SecretHandler) GetSecretVersions(w http.ResponseWriter, r *http.Request) {
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

	versions, err := h.coreService.GetSecretVersionsWithPermissionCheck(r.Context(), uint(id), userCtx.UserID)
	if err != nil {
		log.Printf("Error getting secret versions: %v", err)
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		} else if strings.Contains(err.Error(), "permission denied") {
			h.sendError(w, "Forbidden", "Access denied", http.StatusForbidden, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to get secret versions", http.StatusInternalServerError, nil)
		}
		return
	}

	h.sendSuccess(w, map[string]interface{}{"versions": versions}, "")
}

// RotateSecret handles POST /api/v1/secrets/{id}/rotate
func (h *SecretHandler) RotateSecret(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		h.sendError(w, "BadRequest", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}

	var reqBody struct {
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

	secret, err := h.coreService.RotateSecret(r.Context(), uint(id), []byte(reqBody.NewValue), userCtx.Username)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to rotate secret", http.StatusInternalServerError, nil)
		}
		return
	}

	h.sendSuccess(w, secret, "Secret rotated successfully")
}

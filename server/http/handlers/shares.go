package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/keyorixhq/keyorix/server/validation"
)

// ShareHandler handles secret sharing HTTP requests
type ShareHandler struct {
	coreService *core.KeyorixCore
	validator   *validation.Validator
}

// NewShareHandler creates a new share handler
func NewShareHandler(coreService *core.KeyorixCore) (*ShareHandler, error) {
	return &ShareHandler{
		coreService: coreService,
		validator:   validation.NewValidator(),
	}, nil
}

// ShareSecret handles POST /api/v1/secrets/{id}/share
func (h *ShareHandler) ShareSecret(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	// Parse ID parameter
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}

	// Parse request body
	var reqBody struct {
		RecipientID uint   `json:"recipient_id" validate:"required"`
		IsGroup     bool   `json:"is_group"`
		Permission  string `json:"permission" validate:"required,oneof=read write"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}

	// Validate request
	if err := h.validator.Validate(&reqBody); err != nil {
		h.sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	var shareRecord *models.ShareRecord

	// Handle group sharing differently
	if reqBody.IsGroup {
		// Build group share request
		groupReq := &core.GroupShareSecretRequest{
			SecretID:   uint(id),
			GroupID:    reqBody.RecipientID,
			Permission: reqBody.Permission,
			SharedBy:   userCtx.UserID,
		}

		// Call service for group sharing
		shareRecord, err = h.coreService.ShareSecretWithGroup(r.Context(), groupReq)
	} else {
		// Build user share request
		userReq := &core.ShareSecretRequest{
			SecretID:    uint(id),
			RecipientID: reqBody.RecipientID,
			IsGroup:     false,
			Permission:  reqBody.Permission,
			SharedBy:    userCtx.UserID,
		}

		// Call service for user sharing
		shareRecord, err = h.coreService.ShareSecret(r.Context(), userReq)
	}

	// Handle errors
	if err != nil {
		log.Printf("Error sharing secret: %v", err)
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		} else if strings.Contains(err.Error(), "not authorized") {
			h.sendError(w, "Forbidden", "Not authorized to share this secret", http.StatusForbidden, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to share secret", http.StatusInternalServerError, nil)
		}
		return
	}

	// Send response
	w.WriteHeader(http.StatusCreated)
	h.sendSuccess(w, shareRecord, i18n.T("SuccessSecretShared", nil))
}

// ListSecretShares handles GET /api/v1/secrets/{id}/shares
func (h *ShareHandler) ListSecretShares(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	// Parse ID parameter
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}

	// Call service
	shares, err := h.coreService.ListSecretShares(r.Context(), uint(id))
	if err != nil {
		log.Printf("Error listing secret shares: %v", err)
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to list secret shares", http.StatusInternalServerError, nil)
		}
		return
	}

	// Send response
	response := map[string]interface{}{
		"shares": shares,
	}
	h.sendSuccess(w, response, "")
}

// UpdateSharePermission handles PUT /api/v1/shares/{id}
func (h *ShareHandler) UpdateSharePermission(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	// Parse ID parameter
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid share ID", http.StatusBadRequest, nil)
		return
	}

	// Parse request body
	var reqBody struct {
		Permission string `json:"permission" validate:"required,oneof=read write"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}

	// Validate request
	if err := h.validator.Validate(&reqBody); err != nil {
		h.sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	// Build core request
	req := &core.UpdateShareRequest{
		ShareID:    uint(id),
		Permission: reqBody.Permission,
		UpdatedBy:  userCtx.UserID,
	}

	// Call service
	shareRecord, err := h.coreService.UpdateSharePermission(r.Context(), req)
	if err != nil {
		log.Printf("Error updating share permission: %v", err)
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Share not found", http.StatusNotFound, nil)
		} else if strings.Contains(err.Error(), "not authorized") {
			h.sendError(w, "Forbidden", "Not authorized to update this share", http.StatusForbidden, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to update share permission", http.StatusInternalServerError, nil)
		}
		return
	}

	// Send response
	h.sendSuccess(w, shareRecord, i18n.T("SuccessShareUpdated", nil))
}

// RevokeShare handles DELETE /api/v1/shares/{id}
func (h *ShareHandler) RevokeShare(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	// Parse ID parameter
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid share ID", http.StatusBadRequest, nil)
		return
	}

	// Call service
	err = h.coreService.RevokeShare(r.Context(), uint(id), userCtx.UserID)
	if err != nil {
		log.Printf("Error revoking share: %v", err)
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Share not found", http.StatusNotFound, nil)
		} else if strings.Contains(err.Error(), "not authorized") {
			h.sendError(w, "Forbidden", "Not authorized to revoke this share", http.StatusForbidden, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to revoke share", http.StatusInternalServerError, nil)
		}
		return
	}

	// Send response
	w.WriteHeader(http.StatusNoContent)
}

// ListShares handles GET /api/v1/shares
func (h *ShareHandler) ListShares(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	// Call service to list all shares for the current user
	shares, err := h.coreService.ListSharesByUser(r.Context(), userCtx.UserID)
	if err != nil {
		log.Printf("Error listing shares: %v", err)
		h.sendError(w, "InternalError", "Failed to list shares", http.StatusInternalServerError, nil)
		return
	}

	// Send response
	response := map[string]interface{}{
		"shares": shares,
	}
	h.sendSuccess(w, response, "")
}

// ListSharedSecrets handles GET /api/v1/shared-secrets
func (h *ShareHandler) ListSharedSecrets(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	// Call service
	secrets, err := h.coreService.ListSharedSecrets(r.Context(), userCtx.UserID)
	if err != nil {
		log.Printf("Error listing shared secrets: %v", err)
		h.sendError(w, "InternalError", "Failed to list shared secrets", http.StatusInternalServerError, nil)
		return
	}
	if secrets == nil {
		secrets = []*models.SecretNode{}
	}

	// Send response
	response := map[string]interface{}{
		"secrets": secrets,
	}
	h.sendSuccess(w, response, "")
}

// GetSharingStatusWithIndicators handles GET /api/v1/secrets/{id}/sharing-status
func (h *ShareHandler) GetSharingStatusWithIndicators(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	// Parse ID parameter
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}

	// Call service
	status, err := h.coreService.GetSecretSharingStatusWithIndicators(r.Context(), uint(id), userCtx.UserID)
	if err != nil {
		log.Printf("Error getting sharing status: %v", err)
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		} else if strings.Contains(err.Error(), "permission") {
			h.sendError(w, "Forbidden", "Access denied", http.StatusForbidden, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to get sharing status", http.StatusInternalServerError, nil)
		}
		return
	}

	// Send response
	h.sendSuccess(w, status, "")
}

// RemoveSelfFromShare handles DELETE /api/v1/secrets/{id}/self-share
func (h *ShareHandler) RemoveSelfFromShare(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	// Parse ID parameter
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}

	// Call service
	err = h.coreService.RemoveSelfFromShare(r.Context(), uint(id), userCtx.UserID)
	if err != nil {
		log.Printf("Error removing self from share: %v", err)
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Share not found", http.StatusNotFound, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to remove self from share", http.StatusInternalServerError, nil)
		}
		return
	}

	// Send response
	w.WriteHeader(http.StatusNoContent)
}

// Helper methods for consistent response handling

// sendSuccess sends a successful JSON response
func (h *ShareHandler) sendSuccess(w http.ResponseWriter, data interface{}, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	response := SuccessResponse{
		Data:    data,
		Message: message,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// sendError sends an error JSON response
func (h *ShareHandler) sendError(w http.ResponseWriter, errorType, message string, statusCode int, details interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)

	response := ErrorResponse{
		Error:   errorType,
		Message: message,
		Code:    statusCode,
		Details: details,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding JSON error response: %v", err)
	}
}

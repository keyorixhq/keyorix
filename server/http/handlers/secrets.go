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
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/keyorixhq/keyorix/server/validation"
)

// SecretHandler handles secret-related HTTP requests
type SecretHandler struct {
	coreService *core.KeyorixCore
	validator   *validation.Validator
}

// NewSecretHandler creates a new secret handler
func NewSecretHandler(coreService *core.KeyorixCore) (*SecretHandler, error) {
	return &SecretHandler{
		coreService: coreService,
		validator:   validation.NewValidator(),
	}, nil
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string      `json:"error"`
	Message string      `json:"message"`
	Code    int         `json:"code"`
	Details interface{} `json:"details,omitempty"`
}

// SuccessResponse represents a success response
type SuccessResponse struct {
	Data    interface{} `json:"data"`
	Message string      `json:"message,omitempty"`
}

// ListSecrets handles GET /api/v1/secrets
func (h *SecretHandler) ListSecrets(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	// Parse query parameters
	page := 1
	pageSize := 20
	
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	// Build filter with sharing options
	filter := &models.SecretListFilter{
		Page:     page,
		PageSize: pageSize,
		SortBy:   r.URL.Query().Get("sort_by"),
		SortOrder: r.URL.Query().Get("sort_order"),
	}

	// Parse sharing filters
	if r.URL.Query().Get("show_owned_only") == "true" {
		filter.ShowOwnedOnly = true
	}
	if r.URL.Query().Get("show_shared_only") == "true" {
		filter.ShowSharedOnly = true
	}

	// Parse permission filter
	if permission := r.URL.Query().Get("permission"); permission != "" {
		filter.Permission = permission
	}

	// Parse other filters
	if typeParam := strings.TrimSpace(r.URL.Query().Get("type")); typeParam != "" {
		filter.Type = &typeParam
	}

	// Parse namespace, zone, environment filters
	if namespaceStr := r.URL.Query().Get("namespace_id"); namespaceStr != "" {
		if nsID, err := strconv.ParseUint(namespaceStr, 10, 32); err == nil {
			nsIDUint := uint(nsID)
			filter.NamespaceID = &nsIDUint
		}
	}

	if zoneStr := r.URL.Query().Get("zone_id"); zoneStr != "" {
		if zID, err := strconv.ParseUint(zoneStr, 10, 32); err == nil {
			zIDUint := uint(zID)
			filter.ZoneID = &zIDUint
		}
	}

	if envStr := r.URL.Query().Get("environment_id"); envStr != "" {
		if eID, err := strconv.ParseUint(envStr, 10, 32); err == nil {
			eIDUint := uint(eID)
			filter.EnvironmentID = &eIDUint
		}
	}

	// Call service with sharing information
	response, err := h.coreService.ListSecretsWithSharingInfo(r.Context(), userCtx.UserID, filter)
	if err != nil {
		log.Printf("Error listing secrets: %v", err)
		h.sendError(w, "InternalError", "Failed to list secrets", http.StatusInternalServerError, nil)
		return
	}

	// Resolve namespace, zone, and environment names.
	h.resolveSecretNames(r.Context(), response.Secrets)

	// Send response
	h.sendSuccess(w, response, "")
}

// CreateSecret handles POST /api/v1/secrets
func (h *SecretHandler) CreateSecret(w http.ResponseWriter, r *http.Request) {
	// Get user from context
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	// Parse request body
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

	// Validate request
	if err := h.validator.Validate(&reqBody); err != nil {
		h.sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	// Build core request
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

	// Call service
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

	// Audit log (non-blocking)
	uid, sID, uname, sname := userCtx.UserID, response.ID, userCtx.Username, response.Name
	ip, ua := r.RemoteAddr, r.Header.Get("User-Agent")
	go h.coreService.LogSecretCreated(context.Background(), uid, sID, uname, sname, ip, ua) // #nosec G118

	// Send response
	w.WriteHeader(http.StatusCreated)
	h.sendSuccess(w, response, i18n.T("SuccessSecretCreated", nil))
}

// GetSecret handles GET /api/v1/secrets/{id}
func (h *SecretHandler) GetSecret(w http.ResponseWriter, r *http.Request) {
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

	// Call service with permission check
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

	// Check if requesting decrypted value
	includeValue := r.URL.Query().Get("include_value") == "true"
	var response interface{} = secret
	
	if includeValue {
		// Get the secret value with permission check
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
		
		// Create response with value
		response = map[string]interface{}{
			"secret": secret,
			"value":  string(value),
		}
	}

	// Audit log (non-blocking)
	uid, sID, uname, sname := userCtx.UserID, uint(id), userCtx.Username, secret.Name
	ip, ua := r.RemoteAddr, r.Header.Get("User-Agent")
	go h.coreService.LogSecretRead(context.Background(), uid, sID, uname, sname, ip, ua) // #nosec G118

	// Send response
	h.sendSuccess(w, response, "")
}

// UpdateSecret handles PUT /api/v1/secrets/{id}
func (h *SecretHandler) UpdateSecret(w http.ResponseWriter, r *http.Request) {
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
		Value    string `json:"value,omitempty"`
		MaxReads *int   `json:"max_reads,omitempty" validate:"omitempty,min=1"`
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
	req := &core.UpdateSecretRequest{
		ID:        uint(id),
		MaxReads:  reqBody.MaxReads,
		UpdatedBy: userCtx.Username,
		UserID:    userCtx.UserID, // Add user ID for permission checking
	}

	if reqBody.Value != "" {
		req.Value = []byte(reqBody.Value)
	}

	// Call service with permission check
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

	// Audit log (non-blocking)
	uid, sID, uname, sname := userCtx.UserID, uint(id), userCtx.Username, response.Name
	ip, ua := r.RemoteAddr, r.Header.Get("User-Agent")
	go h.coreService.LogSecretUpdated(context.Background(), uid, sID, uname, sname, ip, ua) // #nosec G118

	// Send response
	h.sendSuccess(w, response, i18n.T("SuccessSecretUpdated", nil))
}

// DeleteSecret handles DELETE /api/v1/secrets/{id}
func (h *SecretHandler) DeleteSecret(w http.ResponseWriter, r *http.Request) {
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

	// Pre-fetch name for audit log before the record is gone.
	secretName := fmt.Sprintf("id=%d", id)
	if s, err := h.coreService.GetSecretWithPermissionCheck(r.Context(), uint(id), userCtx.UserID); err == nil {
		secretName = s.Name
	}

	// Call service with permission check
	err = h.coreService.DeleteSecretWithPermissionCheck(r.Context(), uint(id), userCtx.UserID)
	if err != nil {
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

	// Audit log (non-blocking)
	uid, sID, uname := userCtx.UserID, uint(id), userCtx.Username
	ip, ua := r.RemoteAddr, r.Header.Get("User-Agent")
	go h.coreService.LogSecretDeleted(context.Background(), uid, sID, uname, secretName, ip, ua) // #nosec G118

	// Send response
	w.WriteHeader(http.StatusNoContent)
}

// GetSecretVersions handles GET /api/v1/secrets/{id}/versions
func (h *SecretHandler) GetSecretVersions(w http.ResponseWriter, r *http.Request) {
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

	// Call service with permission check
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

	// Send response
	response := map[string]interface{}{
		"versions": versions,
	}
	h.sendSuccess(w, response, "")
}

// resolveSecretNames populates NamespaceName, ZoneName, and EnvironmentName on each
// secret in the list. It performs one lookup per catalog type and builds ID→name maps,
// so the total cost is 3 queries regardless of list size.
func (h *SecretHandler) resolveSecretNames(ctx context.Context, secrets []*models.SecretWithSharingInfo) {
	if len(secrets) == 0 {
		return
	}

	namespaceNames := make(map[uint]string)
	zoneNames := make(map[uint]string)
	environmentNames := make(map[uint]string)

	if namespaces, err := h.coreService.ListNamespaces(ctx); err == nil {
		for _, ns := range namespaces {
			namespaceNames[ns.ID] = ns.Name
		}
	}
	if zones, err := h.coreService.ListZones(ctx); err == nil {
		for _, z := range zones {
			zoneNames[z.ID] = z.Name
		}
	}
	if environments, err := h.coreService.ListEnvironments(ctx); err == nil {
		for _, e := range environments {
			environmentNames[e.ID] = e.Name
		}
	}

	for _, s := range secrets {
		if s.SecretNode == nil {
			continue
		}
		s.NamespaceName = namespaceNames[s.NamespaceID]
		s.ZoneName = zoneNames[s.ZoneID]
		s.EnvironmentName = environmentNames[s.EnvironmentID]
	}
}

// Helper methods for consistent response handling

// sendSuccess sends a successful JSON response
func (h *SecretHandler) sendSuccess(w http.ResponseWriter, data interface{}, message string) {
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
func (h *SecretHandler) sendError(w http.ResponseWriter, errorType, message string, statusCode int, details interface{}) {
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

// service_accounts_handler.go — HTTP handlers for the service-accounts domain.
//
// Routes (all under /api/v1/service-accounts):
//
//	GET    /                            — List service accounts
//	POST   /                            — Create (returns plain secret once)
//	GET    /{clientId}                  — Get
//	PUT    /{clientId}                  — Update
//	DELETE /{clientId}                  — Revoke (204 No Content)
//	GET    /{clientId}/tokens           — List tokens
//	POST   /{clientId}/tokens           — Create token (returns plain token once)
//	DELETE /{clientId}/tokens/{tokenId} — Revoke token (204 No Content)
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
	"github.com/keyorixhq/keyorix/server/validation"
)

// ServiceAccountHandler handles service account and API token HTTP requests.
type ServiceAccountHandler struct {
	coreService *core.KeyorixCore
	validator   *validation.Validator
}

// NewServiceAccountHandler creates a new ServiceAccountHandler.
func NewServiceAccountHandler(coreService *core.KeyorixCore) *ServiceAccountHandler {
	return &ServiceAccountHandler{
		coreService: coreService,
		validator:   validation.NewValidator(),
	}
}

func (h *ServiceAccountHandler) sendSuccess(w http.ResponseWriter, data interface{}, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := json.NewEncoder(w).Encode(SuccessResponse{Data: data, Message: message}); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *ServiceAccountHandler) sendError(w http.ResponseWriter, errorType, message string, statusCode int, details interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(ErrorResponse{
		Error:   errorType,
		Message: message,
		Code:    statusCode,
		Details: details,
	}); err != nil {
		log.Printf("Error encoding JSON error response: %v", err)
	}
}

// apiClientResponse is the safe DTO for APIClient — omits the stored secret.
type apiClientResponse struct {
	ID          uint      `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	ClientID    string    `json:"client_id"`
	Scopes      string    `json:"scopes"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
}

// apiClientCreatedResponse adds the one-time plain secret to apiClientResponse.
type apiClientCreatedResponse struct {
	apiClientResponse
	ClientSecret string `json:"client_secret"`
}

// apiTokenResponse is the safe DTO for APIToken — omits the stored token value.
type apiTokenResponse struct {
	ID        uint       `json:"id"`
	ClientID  uint       `json:"client_id"`
	UserID    *uint      `json:"user_id,omitempty"`
	Scope     string     `json:"scope"`
	Revoked   bool       `json:"revoked"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// apiTokenCreatedResponse adds the one-time plain token to apiTokenResponse.
type apiTokenCreatedResponse struct {
	apiTokenResponse
	Token string `json:"token"`
}

// --- Service account handlers ---

// ListServiceAccounts handles GET /api/v1/service-accounts
func (h *ServiceAccountHandler) ListServiceAccounts(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	clients, err := h.coreService.ListServiceAccounts(r.Context())
	if err != nil {
		log.Printf("Error listing service accounts: %v", err)
		h.sendError(w, "InternalError", "Failed to list service accounts", http.StatusInternalServerError, nil)
		return
	}

	dtos := make([]apiClientResponse, 0, len(clients))
	for _, c := range clients {
		dtos = append(dtos, apiClientResponse{
			ID:          c.ID,
			Name:        c.Name,
			Description: c.Description,
			ClientID:    c.ClientID,
			Scopes:      c.Scopes,
			IsActive:    c.IsActive,
			CreatedAt:   c.CreatedAt,
		})
	}
	h.sendSuccess(w, dtos, "")
}

// CreateServiceAccount handles POST /api/v1/service-accounts
func (h *ServiceAccountHandler) CreateServiceAccount(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	var reqBody struct {
		Name        string `json:"name" validate:"required,min=1,max=255"`
		Description string `json:"description"`
		Scopes      string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&reqBody); err != nil {
		h.sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	result, err := h.coreService.CreateServiceAccount(r.Context(), &core.CreateServiceAccountRequest{
		Name:        reqBody.Name,
		Description: reqBody.Description,
		Scopes:      reqBody.Scopes,
	})
	if err != nil {
		log.Printf("Error creating service account: %v", err)
		h.sendError(w, "InternalError", "Failed to create service account", http.StatusInternalServerError, nil)
		return
	}

	w.WriteHeader(http.StatusCreated)
	h.sendSuccess(w, apiClientCreatedResponse{
		apiClientResponse: apiClientResponse{
			ID:          result.ID,
			Name:        result.Name,
			Description: result.Description,
			ClientID:    result.ClientID,
			Scopes:      result.Scopes,
			IsActive:    result.IsActive,
			CreatedAt:   result.CreatedAt,
		},
		ClientSecret: result.PlainClientSecret,
	}, "Service account created successfully")
}

// GetServiceAccount handles GET /api/v1/service-accounts/{clientId}
func (h *ServiceAccountHandler) GetServiceAccount(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	clientID := chi.URLParam(r, "clientId")
	client, err := h.coreService.GetServiceAccount(r.Context(), clientID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Service account not found", http.StatusNotFound, nil)
		} else {
			log.Printf("Error getting service account: %v", err)
			h.sendError(w, "InternalError", "Failed to get service account", http.StatusInternalServerError, nil)
		}
		return
	}

	h.sendSuccess(w, apiClientResponse{
		ID:          client.ID,
		Name:        client.Name,
		Description: client.Description,
		ClientID:    client.ClientID,
		Scopes:      client.Scopes,
		IsActive:    client.IsActive,
		CreatedAt:   client.CreatedAt,
	}, "")
}

// UpdateServiceAccount handles PUT /api/v1/service-accounts/{clientId}
func (h *ServiceAccountHandler) UpdateServiceAccount(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	clientID := chi.URLParam(r, "clientId")

	var reqBody struct {
		Name        string `json:"name" validate:"required,min=1,max=255"`
		Description string `json:"description"`
		Scopes      string `json:"scopes"`
		IsActive    bool   `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&reqBody); err != nil {
		h.sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	client, err := h.coreService.UpdateServiceAccount(r.Context(), clientID, &core.UpdateServiceAccountRequest{
		Name:        reqBody.Name,
		Description: reqBody.Description,
		Scopes:      reqBody.Scopes,
		IsActive:    reqBody.IsActive,
	})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Service account not found", http.StatusNotFound, nil)
		} else {
			log.Printf("Error updating service account: %v", err)
			h.sendError(w, "InternalError", "Failed to update service account", http.StatusInternalServerError, nil)
		}
		return
	}

	h.sendSuccess(w, apiClientResponse{
		ID:          client.ID,
		Name:        client.Name,
		Description: client.Description,
		ClientID:    client.ClientID,
		Scopes:      client.Scopes,
		IsActive:    client.IsActive,
		CreatedAt:   client.CreatedAt,
	}, "Service account updated successfully")
}

// DeactivateServiceAccount handles DELETE /api/v1/service-accounts/{clientId}
func (h *ServiceAccountHandler) DeactivateServiceAccount(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	clientID := chi.URLParam(r, "clientId")
	if err := h.coreService.RevokeServiceAccount(r.Context(), clientID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Service account not found", http.StatusNotFound, nil)
		} else {
			log.Printf("Error revoking service account: %v", err)
			h.sendError(w, "InternalError", "Failed to revoke service account", http.StatusInternalServerError, nil)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Token handlers ---

// ListTokens handles GET /api/v1/service-accounts/{clientId}/tokens
func (h *ServiceAccountHandler) ListTokens(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	clientID := chi.URLParam(r, "clientId")
	tokens, err := h.coreService.ListServiceTokens(r.Context(), clientID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Service account not found", http.StatusNotFound, nil)
		} else {
			log.Printf("Error listing tokens: %v", err)
			h.sendError(w, "InternalError", "Failed to list tokens", http.StatusInternalServerError, nil)
		}
		return
	}

	dtos := make([]apiTokenResponse, 0, len(tokens))
	for _, t := range tokens {
		dtos = append(dtos, apiTokenResponse{
			ID:        t.ID,
			ClientID:  t.ClientID,
			UserID:    t.UserID,
			Scope:     t.Scope,
			Revoked:   t.Revoked,
			ExpiresAt: t.ExpiresAt,
			CreatedAt: t.CreatedAt,
		})
	}
	h.sendSuccess(w, dtos, "")
}

// CreateToken handles POST /api/v1/service-accounts/{clientId}/tokens
func (h *ServiceAccountHandler) CreateToken(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	clientID := chi.URLParam(r, "clientId")

	var reqBody struct {
		Scope     string     `json:"scope"`
		ExpiresAt *time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}

	result, err := h.coreService.CreateServiceToken(r.Context(), clientID, &core.CreateServiceTokenRequest{
		Scope:     reqBody.Scope,
		ExpiresAt: reqBody.ExpiresAt,
	})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Service account not found", http.StatusNotFound, nil)
		} else if strings.Contains(err.Error(), "revoked") {
			h.sendError(w, "Forbidden", err.Error(), http.StatusForbidden, nil)
		} else {
			log.Printf("Error creating token: %v", err)
			h.sendError(w, "InternalError", "Failed to create token", http.StatusInternalServerError, nil)
		}
		return
	}

	w.WriteHeader(http.StatusCreated)
	h.sendSuccess(w, apiTokenCreatedResponse{
		apiTokenResponse: apiTokenResponse{
			ID:        result.ID,
			ClientID:  result.ClientID,
			UserID:    result.UserID,
			Scope:     result.Scope,
			Revoked:   result.Revoked,
			ExpiresAt: result.ExpiresAt,
			CreatedAt: result.CreatedAt,
		},
		Token: result.PlainToken,
	}, "API token created successfully")
}

// RevokeToken handles DELETE /api/v1/service-accounts/{clientId}/tokens/{tokenId}
func (h *ServiceAccountHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	tokenIDStr := chi.URLParam(r, "tokenId")
	tokenID, err := strconv.ParseUint(tokenIDStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid token ID", http.StatusBadRequest, nil)
		return
	}

	if err := h.coreService.RevokeServiceToken(r.Context(), uint(tokenID)); err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Token not found", http.StatusNotFound, nil)
		} else {
			log.Printf("Error revoking token: %v", err)
			h.sendError(w, "InternalError", "Failed to revoke token", http.StatusInternalServerError, nil)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

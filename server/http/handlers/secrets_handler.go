// Package handlers provides HTTP handlers for the Keyorix API.
//
// # Secrets domain entry point
//
// SecretHandler methods are spread across focused files:
//
//   - secrets_list.go    — ListSecrets (GET /api/v1/secrets)
//   - secrets_crud.go    — CreateSecret, GetSecret, UpdateSecret, DeleteSecret
//   - secrets_versions.go — GetSecretVersions, RotateSecret
//
// Shared types (ErrorResponse, SuccessResponse) and helpers (sendSuccess,
// sendError, resolveSecretNames) live here and are used by all three files.
package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/validation"
)

// SecretHandler handles secret-related HTTP requests.
type SecretHandler struct {
	coreService *core.KeyorixCore
	validator   *validation.Validator
}

// NewSecretHandler creates a new SecretHandler.
func NewSecretHandler(coreService *core.KeyorixCore) (*SecretHandler, error) {
	return &SecretHandler{
		coreService: coreService,
		validator:   validation.NewValidator(),
	}, nil
}

// ErrorResponse is the standard error envelope returned on all 4xx/5xx responses.
type ErrorResponse struct {
	Error   string      `json:"error"`
	Message string      `json:"message"`
	Code    int         `json:"code"`
	Details interface{} `json:"details,omitempty"`
}

// SuccessResponse is the standard success envelope returned on 2xx responses.
type SuccessResponse struct {
	Data    interface{} `json:"data"`
	Message string      `json:"message,omitempty"`
}

// sendSuccess writes a 200 JSON response with the SuccessResponse envelope.
func (h *SecretHandler) sendSuccess(w http.ResponseWriter, data interface{}, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := json.NewEncoder(w).Encode(SuccessResponse{Data: data, Message: message}); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// sendError writes an error JSON response with the given status code.
func (h *SecretHandler) sendError(w http.ResponseWriter, errorType, message string, statusCode int, details interface{}) {
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

// resolveSecretNames populates NamespaceName, ZoneName, and EnvironmentName on
// each secret in the list. Performs one lookup per catalog type (3 queries total
// regardless of list size) and builds ID→name maps.
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

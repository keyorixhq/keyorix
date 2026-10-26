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

// sendSuccess writes a 200 JSON response with the SuccessResponse envelope.
func (h *SecretHandler) sendSuccess(w http.ResponseWriter, data any, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := encodeJSONResponse(w, SuccessResponse{Success: true, Data: data, Message: message}); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// sendError writes an error JSON response with the given status code.
func (h *SecretHandler) sendError(w http.ResponseWriter, errorType, message string, statusCode int, details any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)
	if err := encodeJSONResponse(w, ErrorResponse{
		Error:   errorType,
		Message: message,
		Code:    statusCode,
		Details: details,
	}); err != nil {
		log.Printf("Error encoding JSON error response: %v", err)
	}
}

// resolveSecretNames populates ProjectName and EnvironmentName on
// each secret in the list. Performs one lookup per catalog type and builds ID→name maps.
func (h *SecretHandler) resolveSecretNames(ctx context.Context, secrets []*models.SecretWithSharingInfo) {
	if len(secrets) == 0 {
		return
	}

	projectNames := make(map[uint]string)
	environmentNames := make(map[uint]string)

	if projects, err := h.coreService.ListProjects(ctx); err == nil {
		for _, p := range projects {
			projectNames[p.ID] = p.Name
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
		s.ProjectName = projectNames[s.ProjectID]
		s.EnvironmentName = environmentNames[s.EnvironmentID]
	}
}

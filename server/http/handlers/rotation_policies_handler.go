// rotation_policies_handler.go — HTTP handlers for the rotation policies domain.
//
// Routes (all under /api/v1/rotation-policies):
//
//	GET    /                — List (with optional project_id / environment_id query params)
//	POST   /                — Create
//	GET    /evaluate        — Evaluate (with optional project_id query param)
//	GET    /{id}            — Get
//	PUT    /{id}            — Update
//	DELETE /{id}            — Delete (204 No Content)
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
	"github.com/keyorixhq/keyorix/server/validation"
)

// RotationPolicyHandler handles rotation policy HTTP requests.
type RotationPolicyHandler struct {
	coreService *core.KeyorixCore
	validator   *validation.Validator
}

// NewRotationPolicyHandler creates a new RotationPolicyHandler.
func NewRotationPolicyHandler(coreService *core.KeyorixCore) *RotationPolicyHandler {
	return &RotationPolicyHandler{
		coreService: coreService,
		validator:   validation.NewValidator(),
	}
}

func (h *RotationPolicyHandler) sendSuccess(w http.ResponseWriter, data interface{}, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := json.NewEncoder(w).Encode(SuccessResponse{Data: data, Message: message}); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *RotationPolicyHandler) sendError(w http.ResponseWriter, errorType, message string, statusCode int, details interface{}) {
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

// List handles GET /api/v1/rotation-policies
func (h *RotationPolicyHandler) List(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	var projectID *uint
	var environmentID *uint

	if v := r.URL.Query().Get("project_id"); v != "" {
		id, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			h.sendError(w, "InvalidParameter", "Invalid project_id", http.StatusBadRequest, nil)
			return
		}
		uid := uint(id)
		projectID = &uid
	}
	if v := r.URL.Query().Get("environment_id"); v != "" {
		id, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			h.sendError(w, "InvalidParameter", "Invalid environment_id", http.StatusBadRequest, nil)
			return
		}
		uid := uint(id)
		environmentID = &uid
	}

	policies, err := h.coreService.ListRotationPolicies(r.Context(), projectID, environmentID)
	if err != nil {
		log.Printf("Error listing rotation policies: %v", err)
		h.sendError(w, "InternalError", "Failed to list rotation policies", http.StatusInternalServerError, nil)
		return
	}

	h.sendSuccess(w, policies, "")
}

// Create handles POST /api/v1/rotation-policies
func (h *RotationPolicyHandler) Create(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	var reqBody struct {
		Name            string `json:"name" validate:"required,min=1,max=255"`
		Description     string `json:"description"`
		Scope           string `json:"scope" validate:"required,oneof=project environment"`
		ProjectID       *uint  `json:"project_id"`
		EnvironmentID   *uint  `json:"environment_id"`
		IntervalDays    int    `json:"interval_days" validate:"required,min=1,max=365"`
		AlertDaysBefore int    `json:"alert_days_before" validate:"min=0,max=90"`
		NotifyOnBreach  bool   `json:"notify_on_breach"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&reqBody); err != nil {
		h.sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	// Authorize against the policy's target scope from the body.
	var pid, eid uint
	if reqBody.ProjectID != nil {
		pid = *reqBody.ProjectID
	}
	if reqBody.EnvironmentID != nil {
		eid = *reqBody.EnvironmentID
	}
	scope := core.Scope{ProjectID: pid, EnvironmentID: eid}
	if allowed, err := h.coreService.AuthorizePrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), "secrets.write", scope); err != nil || !allowed {
		h.sendError(w, "Forbidden", "Insufficient permissions", http.StatusForbidden, nil)
		return
	}

	req := &core.CreateRotationPolicyRequest{
		Name:            reqBody.Name,
		Description:     reqBody.Description,
		Scope:           reqBody.Scope,
		ProjectID:       reqBody.ProjectID,
		EnvironmentID:   reqBody.EnvironmentID,
		IntervalDays:    reqBody.IntervalDays,
		AlertDaysBefore: reqBody.AlertDaysBefore,
		NotifyOnBreach:  reqBody.NotifyOnBreach,
		CreatedBy:       userCtx.Username,
	}

	policy, err := h.coreService.CreateRotationPolicy(r.Context(), req)
	if err != nil {
		log.Printf("Error creating rotation policy: %v", err)
		if strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "must be less than") {
			h.sendError(w, "ValidationError", err.Error(), http.StatusUnprocessableEntity, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to create rotation policy", http.StatusInternalServerError, nil)
		}
		return
	}

	w.WriteHeader(http.StatusCreated)
	h.sendSuccess(w, policy, "Rotation policy created successfully")
}

// Get handles GET /api/v1/rotation-policies/{id}
func (h *RotationPolicyHandler) Get(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid rotation policy ID", http.StatusBadRequest, nil)
		return
	}

	policy, err := h.coreService.GetRotationPolicy(r.Context(), uint(id))
	if err != nil {
		log.Printf("Error getting rotation policy: %v", err)
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Rotation policy not found", http.StatusNotFound, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to get rotation policy", http.StatusInternalServerError, nil)
		}
		return
	}

	h.sendSuccess(w, policy, "")
}

// Update handles PUT /api/v1/rotation-policies/{id}
func (h *RotationPolicyHandler) Update(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid rotation policy ID", http.StatusBadRequest, nil)
		return
	}

	var reqBody struct {
		Name            string `json:"name" validate:"required,min=1,max=255"`
		Description     string `json:"description"`
		IntervalDays    int    `json:"interval_days" validate:"required,min=1,max=365"`
		AlertDaysBefore int    `json:"alert_days_before" validate:"min=0,max=90"`
		NotifyOnBreach  bool   `json:"notify_on_breach"`
		IsActive        bool   `json:"is_active"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if err := h.validator.Validate(&reqBody); err != nil {
		h.sendError(w, "ValidationError", "Invalid request data", http.StatusBadRequest, err)
		return
	}

	req := &core.UpdateRotationPolicyRequest{
		ID:              uint(id),
		Name:            reqBody.Name,
		Description:     reqBody.Description,
		IntervalDays:    reqBody.IntervalDays,
		AlertDaysBefore: reqBody.AlertDaysBefore,
		NotifyOnBreach:  reqBody.NotifyOnBreach,
		IsActive:        reqBody.IsActive,
	}

	policy, err := h.coreService.UpdateRotationPolicy(r.Context(), req)
	if err != nil {
		log.Printf("Error updating rotation policy: %v", err)
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Rotation policy not found", http.StatusNotFound, nil)
		} else if strings.Contains(err.Error(), "must be less than") {
			h.sendError(w, "ValidationError", err.Error(), http.StatusUnprocessableEntity, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to update rotation policy", http.StatusInternalServerError, nil)
		}
		return
	}

	h.sendSuccess(w, policy, "Rotation policy updated successfully")
}

// Delete handles DELETE /api/v1/rotation-policies/{id}
func (h *RotationPolicyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid rotation policy ID", http.StatusBadRequest, nil)
		return
	}

	if err := h.coreService.DeleteRotationPolicy(r.Context(), uint(id)); err != nil {
		log.Printf("Error deleting rotation policy: %v", err)
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Rotation policy not found", http.StatusNotFound, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to delete rotation policy", http.StatusInternalServerError, nil)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Evaluate handles GET /api/v1/rotation-policies/evaluate
func (h *RotationPolicyHandler) Evaluate(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	var projectID *uint
	if v := r.URL.Query().Get("project_id"); v != "" {
		id, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			h.sendError(w, "InvalidParameter", "Invalid project_id", http.StatusBadRequest, nil)
			return
		}
		uid := uint(id)
		projectID = &uid
	}

	evaluations, err := h.coreService.EvaluateRotationPolicies(r.Context(), projectID)
	if err != nil {
		log.Printf("Error evaluating rotation policies: %v", err)
		h.sendError(w, "InternalError", "Failed to evaluate rotation policies", http.StatusInternalServerError, nil)
		return
	}

	h.sendSuccess(w, evaluations, "")
}

// Status handles GET /api/v1/rotation-policies/status — the rotation posture of
// every policy-covered secret (overdue / due_soon / ok), powering the dashboard
// rotation inspector and health score. Unlike Evaluate it does not filter to
// only overdue/approaching secrets.
func (h *RotationPolicyHandler) Status(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	var projectID *uint
	if v := r.URL.Query().Get("project_id"); v != "" {
		id, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			h.sendError(w, "InvalidParameter", "Invalid project_id", http.StatusBadRequest, nil)
			return
		}
		uid := uint(id)
		projectID = &uid
	}

	entries, err := h.coreService.GetRotationStatus(r.Context(), projectID)
	if err != nil {
		log.Printf("Error getting rotation status: %v", err)
		h.sendError(w, "InternalError", "Failed to get rotation status", http.StatusInternalServerError, nil)
		return
	}

	h.sendSuccess(w, entries, "")
}

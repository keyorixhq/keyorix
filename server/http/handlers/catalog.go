package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// CatalogHandler handles project and environment endpoints.
type CatalogHandler struct {
	coreService *core.KeyorixCore
}

// NewCatalogHandler creates a new CatalogHandler.
func NewCatalogHandler(svc *core.KeyorixCore) *CatalogHandler {
	return &CatalogHandler{coreService: svc}
}

// ListProjects handles GET /api/v1/projects — returns projects with secret and
// environment counts. Pass ?include_deleted=true to also return soft-deleted
// projects (flagged via the deleted/deleted_at fields) for the restore UI.
func (h *CatalogHandler) ListProjects(w http.ResponseWriter, r *http.Request) {
	includeDeleted := r.URL.Query().Get("include_deleted") == "true"
	projects, err := h.coreService.ListProjectsWithCounts(r.Context(), includeDeleted)
	if err != nil {
		sendError(w, "Failed to list projects", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"projects": projects}, "")
}

// RestoreProject handles POST /api/v1/projects/{id}/restore
func (h *CatalogHandler) RestoreProject(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.RestoreProject(r.Context(), uint(id)); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	sendSuccess(w, nil, "Project restored")
}

// GetProject handles GET /api/v1/projects/:id
func (h *CatalogHandler) GetProject(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	project, err := h.coreService.GetProject(r.Context(), uint(id))
	if err != nil {
		sendError(w, "NotFound", err.Error(), http.StatusNotFound, nil)
		return
	}
	sendSuccess(w, project, "")
}

// CreateProject handles POST /api/v1/projects
func (h *CatalogHandler) CreateProject(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	project, err := h.coreService.CreateProject(r.Context(), body.Name, body.Description)
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, project, "Project created")
}

// ListEnvironments handles GET /api/v1/environments (global, for backward compat)
func (h *CatalogHandler) ListEnvironments(w http.ResponseWriter, r *http.Request) {
	environments, err := h.coreService.ListEnvironments(r.Context())
	if err != nil {
		sendError(w, "Failed to list environments", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"environments": environments}, "")
}

// UpdateProject handles PUT /api/v1/projects/:id
func (h *CatalogHandler) UpdateProject(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	project, err := h.coreService.UpdateProject(r.Context(), uint(id), body.Name, body.Description)
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, project, "Project updated")
}

// DeleteProject handles DELETE /api/v1/projects/:id
// Accepts ?force=true to cascade-delete even when the project contains secrets.
func (h *CatalogHandler) DeleteProject(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	force := r.URL.Query().Get("force") == "true"
	if err := h.coreService.DeleteProject(r.Context(), uint(id), force); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "secret(s)") {
			status = http.StatusConflict
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	sendSuccess(w, nil, "Project deleted")
}

// CreateProjectEnvironment handles POST /api/v1/projects/:id/environments
func (h *CatalogHandler) CreateProjectEnvironment(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if body.Name == "" {
		sendError(w, "ValidationError", "Environment name is required", http.StatusBadRequest, nil)
		return
	}
	env, err := h.coreService.Storage().CreateEnvironment(r.Context(), &models.Environment{
		ProjectID: uint(id),
		Name:      body.Name,
	})
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, env, "Environment created")
}

// DeleteEnvironment handles DELETE /api/v1/environments/:id
func (h *CatalogHandler) DeleteEnvironment(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid environment ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.DeleteEnvironment(r.Context(), uint(id)); err != nil {
		msg := err.Error()
		status := http.StatusInternalServerError
		if strings.Contains(msg, "active secret") {
			status = http.StatusConflict
		} else if strings.Contains(msg, "not found") {
			status = http.StatusNotFound
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, nil, "Environment deleted")
}

// ListProjectEnvironments handles GET /api/v1/projects/:id/environments.
// Pass ?include_deleted=true to also return soft-deleted environments.
func (h *CatalogHandler) ListProjectEnvironments(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	var environments []*models.Environment
	if r.URL.Query().Get("include_deleted") == "true" {
		environments, err = h.coreService.ListEnvironmentsByProjectIncludingDeleted(r.Context(), uint(id))
	} else {
		environments, err = h.coreService.ListEnvironmentsByProject(r.Context(), uint(id))
	}
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"environments": environments}, "")
}

// RestoreEnvironment handles POST /api/v1/projects/{projectId}/environments/{id}/restore.
// Nested under the project so the permission scope resolves from the project ID
// (the environment row itself is soft-deleted and not loadable by the scope check).
func (h *CatalogHandler) RestoreEnvironment(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid environment ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.RestoreEnvironment(r.Context(), uint(id)); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	sendSuccess(w, nil, "Environment restored")
}

package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// actorID returns the acting user's ID from the request context (0 when absent).
func actorID(r *http.Request) uint {
	if u := middleware.GetUserFromContext(r.Context()); u != nil {
		return u.UserID
	}
	return 0
}

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
	if err := h.coreService.RestoreProject(r.Context(), actorID(r), uint(id)); err != nil {
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

// GetProjectDrift handles GET /api/v1/projects/{id}/drift — the
// cross-environment drift report for the project (keys missing in some
// environments, or present everywhere with diverging settings).
func (h *CatalogHandler) GetProjectDrift(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	report, err := h.coreService.DetectProjectDrift(r.Context(), uint(id))
	if err != nil {
		sendError(w, "InternalError", "Failed to compute drift", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, report, "")
}

// CreateProject handles POST /api/v1/projects
func (h *CatalogHandler) CreateProject(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		// Environments, when non-empty, seeds the project with exactly these
		// environments instead of the default development/staging/production set —
		// one call for infrastructure-as-code provisioning. Blank entries are dropped.
		Environments []string `json:"environments"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	envs := make([]string, 0, len(body.Environments))
	for _, e := range body.Environments {
		if e = strings.TrimSpace(e); e != "" {
			envs = append(envs, e)
		}
	}

	var project *models.Project
	var err error
	if len(envs) > 0 {
		project, err = h.coreService.CreateProjectWithEnvs(r.Context(), body.Name, body.Description, envs)
	} else {
		project, err = h.coreService.CreateProject(r.Context(), body.Name, body.Description)
	}
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
		RequireMFA  *bool  `json:"require_mfa"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	project, err := h.coreService.UpdateProject(r.Context(), uint(id), body.Name, body.Description, body.RequireMFA)
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
	// The scope check resolves the project id from the URL without verifying it exists,
	// so confirm the parent project is live before creating an environment under it —
	// otherwise a caller who held write on a since-deleted project could re-establish a
	// usable scope under it (GetProject excludes soft-deleted projects).
	if _, perr := h.coreService.Storage().GetProject(r.Context(), uint(id)); perr != nil {
		sendError(w, "NotFound", "Project not found", http.StatusNotFound, nil)
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
	projectID, err := strconv.ParseUint(chi.URLParam(r, "projectId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid environment ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.RestoreEnvironment(r.Context(), actorID(r), uint(projectID), uint(id)); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	sendSuccess(w, nil, "Environment restored")
}

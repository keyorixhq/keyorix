package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
)

// CatalogHandler handles project and environment endpoints.
type CatalogHandler struct {
	coreService *core.KeyorixCore
}

// NewCatalogHandler creates a new CatalogHandler.
func NewCatalogHandler(svc *core.KeyorixCore) *CatalogHandler {
	return &CatalogHandler{coreService: svc}
}

// ListProjects handles GET /api/v1/projects
func (h *CatalogHandler) ListProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := h.coreService.ListProjects(r.Context())
	if err != nil {
		sendError(w, "Failed to list projects", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"projects": projects}, "")
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

// ListProjectEnvironments handles GET /api/v1/projects/:id/environments
func (h *CatalogHandler) ListProjectEnvironments(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	environments, err := h.coreService.ListEnvironmentsByProject(r.Context(), uint(id))
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"environments": environments}, "")
}

package handlers

import (
	"net/http"

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

// ListEnvironments handles GET /api/v1/environments
func (h *CatalogHandler) ListEnvironments(w http.ResponseWriter, r *http.Request) {
	environments, err := h.coreService.ListEnvironments(r.Context())
	if err != nil {
		sendError(w, "Failed to list environments", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"environments": environments}, "")
}

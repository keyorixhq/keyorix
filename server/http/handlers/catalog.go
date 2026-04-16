package handlers

import (
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
)

// CatalogHandler handles namespace, zone, and environment endpoints.
type CatalogHandler struct {
	coreService *core.KeyorixCore
}

// NewCatalogHandler creates a new CatalogHandler.
func NewCatalogHandler(svc *core.KeyorixCore) *CatalogHandler {
	return &CatalogHandler{coreService: svc}
}

// ListNamespaces handles GET /api/v1/namespaces
func (h *CatalogHandler) ListNamespaces(w http.ResponseWriter, r *http.Request) {
	namespaces, err := h.coreService.ListNamespaces(r.Context())
	if err != nil {
		sendError(w, "Failed to list namespaces", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"namespaces": namespaces}, "")
}

// ListZones handles GET /api/v1/zones
func (h *CatalogHandler) ListZones(w http.ResponseWriter, r *http.Request) {
	zones, err := h.coreService.ListZones(r.Context())
	if err != nil {
		sendError(w, "Failed to list zones", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"zones": zones}, "")
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

// project_health.go — project-level secret health summary handler.
//
// Route (under /api/v1/projects):
//
//	GET /{id}/health[?limit=N]  — top-N highest-risk secrets in the project
package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// GetProjectHealth handles GET /api/v1/projects/{id}/health[?limit=N]
//
// Returns the top-N highest-risk secrets in the project together with band
// counts. N defaults to 20 and is capped at 100 (clamping is done in core).
// Requires secrets.read at the project scope (enforced by the route middleware).
func (h *SecretHandler) GetProjectHealth(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}

	limit := 20
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		parsed, err := strconv.Atoi(lStr)
		if err != nil || parsed <= 0 {
			h.sendError(w, "InvalidParameter", "limit must be a positive integer", http.StatusBadRequest, nil)
			return
		}
		limit = parsed
	}

	summary, err := h.coreService.GetProjectHealthSummary(r.Context(), uint(id), limit)
	if err != nil {
		h.sendError(w, "InternalError", "Failed to compute project health", http.StatusInternalServerError, nil)
		return
	}

	h.sendSuccess(w, summary, "")
}

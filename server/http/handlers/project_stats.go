// project_stats.go — GET /api/v1/projects/{id}/stats handler.
//
// Returns rich per-project statistics derived from existing data:
// secret counts, rotation health, unique accessors, open anomalies, and a
// classification breakdown. Requires secrets.read at the project scope.
package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/errclass"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// GetProjectStats handles GET /api/v1/projects/{id}/stats.
//
// Requires secrets.read scoped to the project (enforced by the route
// middleware in router.go). Returns a ProjectStats JSON object.
func (h *SecretHandler) GetProjectStats(w http.ResponseWriter, r *http.Request) {
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

	stats, err := h.coreService.GetProjectStats(r.Context(), uint(id))
	if err != nil {
		// A missing project is 404, not 500 (#4132 OPENAPI-STATEFUL-3).
		answerCoreError(w, r, err, coreErrorAnswer{op: "computing project stats", texts: coreErrorTexts{
			errclass.NotFound: "Project not found",
			errclass.Internal: "Failed to compute project stats",
		}})
		return
	}

	h.sendSuccess(w, stats, "")
}

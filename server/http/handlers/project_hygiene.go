// project_hygiene.go — ProjectHygiene handler: a project's security-hygiene posture
// (counts of orphaned / unused / expiring secrets and stale machine identities).
package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ProjectHygiene handles GET /api/v1/projects/{id}/hygiene — a one-call posture summary
// for the project (counts only). Scoped secrets.read (project) is enforced by the
// router. Optional ?unused_days / ?expiring_days / ?stale_days override the windows.
func (h *SecretHandler) ProjectHygiene(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "BadRequest", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	qint := func(key string) int {
		if v := r.URL.Query().Get(key); v != "" {
			if n, perr := strconv.Atoi(v); perr == nil {
				return n
			}
		}
		return 0
	}

	summary, err := h.coreService.ProjectHygieneSummary(r.Context(), uint(id),
		qint("unused_days"), qint("expiring_days"), qint("stale_days"))
	if err != nil {
		h.sendError(w, "InternalError", "Failed to compute hygiene summary", http.StatusInternalServerError, nil)
		return
	}
	h.sendSuccess(w, summary, "")
}

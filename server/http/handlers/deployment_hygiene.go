// deployment_hygiene.go — DeploymentHygiene handler: the install-wide hygiene rollup
// (per-project posture summed across every project, plus a breakdown of the projects
// that carry debt). Counts only, but names every project deployment-wide. Deployment-
// wide audit.read is enforced by the router (not the universal system_viewer baseline).
package handlers

import (
	"net/http"
	"strconv"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// DeploymentHygiene handles GET /api/v1/hygiene — one call returning install-wide
// hygiene totals + the projects with outstanding signals (counts only). Optional
// ?unused_days / ?expiring_days / ?stale_days override the per-project windows.
func (h *SecretHandler) DeploymentHygiene(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
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

	summary, err := h.coreService.DeploymentHygieneSummary(r.Context(),
		qint("unused_days"), qint("expiring_days"), qint("stale_days"))
	if err != nil {
		h.sendError(w, "InternalError", "Failed to compute hygiene rollup", http.StatusInternalServerError, nil)
		return
	}
	h.sendSuccess(w, summary, "")
}

// permission_change_audit.go — HTTP handler for the permission change audit
// trail endpoint.
//
//	GET /api/v1/compliance/permission-changes?since=RFC3339&until=RFC3339&limit=N
//
// Returns a PermissionChangeReport (structured JSON). Requires audit.read.
// The handler lives on DashboardHandler (same as the other /compliance/…
// endpoints) so it shares the existing router registration pattern with no new
// struct to wire in.
package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// GetPermissionChangeAudit handles GET /api/v1/compliance/permission-changes.
// Query parameters (all optional):
//
//	since — RFC3339 lower bound (default: 30 days ago)
//	until — RFC3339 upper bound (default: now)
//	limit — max results to return (default 100, max 1000)
func (h *DashboardHandler) GetPermissionChangeAudit(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	var since, until time.Time

	if s := r.URL.Query().Get("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			sendError(w, "BadRequest", "invalid since parameter: must be RFC3339", http.StatusBadRequest, nil)
			return
		}
		since = t
	}

	if u := r.URL.Query().Get("until"); u != "" {
		t, err := time.Parse(time.RFC3339, u)
		if err != nil {
			sendError(w, "BadRequest", "invalid until parameter: must be RFC3339", http.StatusBadRequest, nil)
			return
		}
		until = t
	}

	limit := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err == nil && n > 0 {
			limit = n
		}
	}

	report, err := h.coreService.GetPermissionChangeAudit(r.Context(), since, until, limit)
	if err != nil {
		sendError(w, "InternalError", "Failed to generate permission change audit", http.StatusInternalServerError, nil)
		return
	}

	sendSuccess(w, report, "")
}

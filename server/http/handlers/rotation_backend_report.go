// rotation_backend_report.go — HTTP handler for the deployment-wide rotation-overdue
// report grouped by RotationBackend.
//
// Route: GET /api/v1/compliance/rotation-by-backend
// Permission: audit.read (global) — same disclosure family as /compliance/evidence.
package handlers

import (
	"log"
	"net/http"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// RotationByBackend handles GET /api/v1/compliance/rotation-by-backend.
// Returns a RotationBackendReport: per-backend counts of overdue / up-to-date /
// never-rotated secrets across the whole deployment, sorted by overdue count
// descending so the worst offenders appear first.
func (h *SecretHandler) RotationByBackend(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	report, err := h.coreService.GetRotationBackendReport(r.Context())
	if err != nil {
		log.Printf("rotation-by-backend: %v", err)
		h.sendError(w, "InternalError", "Failed to build rotation-by-backend report", http.StatusInternalServerError, nil)
		return
	}
	h.sendSuccess(w, report, "")
}

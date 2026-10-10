// compliance_snapshots_handler.go — POST and GET /api/v1/compliance/snapshots.
//
// POST triggers a fresh compliance posture evaluation and persists the result as
// a dated snapshot (idempotent within a calendar day — a repeat call returns the
// updated same-day row).
//
// GET lists stored snapshots (most recent first; optional limit query param).
package handlers

import (
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// TakeComplianceSnapshot handles POST /api/v1/compliance/snapshots.
func (h *DashboardHandler) TakeComplianceSnapshot(w http.ResponseWriter, r *http.Request) {
	snap, err := h.coreService.TakeComplianceSnapshot(r.Context())
	if err != nil {
		log.Printf("Error taking compliance snapshot: %v", err)
		// Fail closed (#2834): a degraded posture is never persisted. No
		// compliance.snapshot_taken audit event is written on any failure, matching
		// this endpoint's existing failure path (log + error response only).
		if errors.Is(err, core.ErrCompliancePostureDegraded) {
			sendError(w, "SnapshotDegraded",
				"Compliance snapshot not taken: some posture data could not be read ("+err.Error()+")",
				http.StatusServiceUnavailable, nil)
			return
		}
		sendError(w, "InternalError", "Failed to take compliance snapshot", http.StatusInternalServerError, nil)
		return
	}
	var actorID uint
	if userCtx := middleware.GetUserFromContext(r.Context()); userCtx != nil {
		actorID = userCtx.UserID
	}
	h.coreService.LogComplianceSnapshotTaken(r.Context(), actorID, snap)
	sendSuccess(w, snap, "")
}

// ListComplianceSnapshots handles GET /api/v1/compliance/snapshots.
func (h *DashboardHandler) ListComplianceSnapshots(w http.ResponseWriter, r *http.Request) {
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			sendError(w, "InvalidParameter", "'limit' must be a non-negative integer", http.StatusBadRequest, nil)
			return
		}
		limit = n
	}

	snaps, err := h.coreService.ListComplianceSnapshots(r.Context(), limit)
	if err != nil {
		log.Printf("Error listing compliance snapshots: %v", err)
		sendError(w, "InternalError", "Failed to list compliance snapshots", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, snaps, "")
}

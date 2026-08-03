// hygiene_trends.go — HTTP handlers for credential-hygiene trend data.
//
// GET  /api/v1/compliance/credential-trends?days=30|60|90
//
//	Returns a HygieneTrendsReport (per-day stale/expired PAT + stale machine counts).
//	Gated on audit.read in the router.
//
// POST /api/v1/system/admin/jobs/record-hygiene-snapshot
//
//	Triggers RecordHygieneTrendPoint: computes today's counts and persists a
//	HygieneTrendSnapshot row. Gated on system.write in the router.
package handlers

import (
	"log"
	"net/http"
	"strconv"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// HygieneTrendsHandler handles the credential-hygiene trend endpoints.
type HygieneTrendsHandler struct {
	coreService *core.KeyorixCore
}

// NewHygieneTrendsHandler creates a new HygieneTrendsHandler.
func NewHygieneTrendsHandler(coreService *core.KeyorixCore) *HygieneTrendsHandler {
	return &HygieneTrendsHandler{coreService: coreService}
}

// GetCredentialTrends handles GET /api/v1/compliance/credential-trends?days=30|60|90.
// Returns a HygieneTrendsReport with per-day stale/expired PAT and stale machine counts.
func (h *HygieneTrendsHandler) GetCredentialTrends(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		if d, err := strconv.Atoi(v); err == nil {
			days = d
		}
		// invalid / non-integer values silently default to 30 (clamped in core)
	}

	report, err := h.coreService.GetHygieneTrends(r.Context(), days)
	if err != nil {
		log.Printf("Error computing credential hygiene trends: %v", err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, report, "")
}

// RecordHygieneSnapshot handles POST /api/v1/system/admin/jobs/record-hygiene-snapshot.
// Computes today's hygiene counts and persists them as a HygieneTrendSnapshot row.
func (h *HygieneTrendsHandler) RecordHygieneSnapshot(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	point, err := h.coreService.RecordHygieneTrendPoint(r.Context())
	if err != nil {
		log.Printf("Error recording hygiene trend snapshot: %v", err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, point, "")
}

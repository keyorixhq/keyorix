// legal_hold.go — deployment-wide legal-hold endpoints (ISO 27001 A.5.34). Status
// reads need audit.read (discloses the free-text hold reason, so the universal
// system_viewer baseline is not enough); placing/lifting needs system.write (wired in
// router.go).
package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// GetLegalHold handles GET /api/v1/legal-hold — the current hold (or {active:false}).
func (h *DashboardHandler) GetLegalHold(w http.ResponseWriter, r *http.Request) {
	hold, err := h.coreService.GetActiveLegalHold(r.Context())
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	if hold == nil {
		sendSuccess(w, map[string]interface{}{"active": false}, "")
		return
	}
	sendSuccess(w, map[string]interface{}{"active": true, "hold": hold}, "")
}

// PlaceLegalHold handles POST /api/v1/legal-hold — activate a hold with a reason.
func (h *DashboardHandler) PlaceLegalHold(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	hold, err := h.coreService.PlaceLegalHold(r.Context(), actor.UserID, body.Reason)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "already active"):
			status = http.StatusBadRequest
		case strings.Contains(err.Error(), "admin-tier principal may place"):
			status = http.StatusForbidden
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, map[string]interface{}{"hold": hold}, "Legal hold placed")
}

// LiftLegalHold handles DELETE /api/v1/legal-hold — release the active hold. The
// reason is carried in a JSON body since DELETE requests conventionally have no
// query-string convention for this codebase's other DELETE-with-body endpoints.
func (h *DashboardHandler) LiftLegalHold(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if r.Body != nil {
		// Body is optional at the transport level; LiftLegalHold itself enforces
		// that reason is non-empty, mapped to 400 below.
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	if err := h.coreService.LiftLegalHold(r.Context(), actor.UserID, body.Reason); err != nil {
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "no legal hold") || strings.Contains(err.Error(), "a reason is required"):
			status = http.StatusBadRequest
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	sendSuccess(w, nil, "Legal hold lifted")
}

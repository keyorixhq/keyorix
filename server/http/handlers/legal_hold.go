// legal_hold.go — deployment-wide legal-hold endpoints (ISO 27001 A.5.34). Status
// reads need system.read; placing/lifting needs system.write (wired in router.go).
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
		if strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "already active") {
			status = http.StatusBadRequest
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, map[string]interface{}{"hold": hold}, "Legal hold placed")
}

// LiftLegalHold handles DELETE /api/v1/legal-hold — release the active hold.
func (h *DashboardHandler) LiftLegalHold(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	if err := h.coreService.LiftLegalHold(r.Context(), actor.UserID); err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "no legal hold") {
			status = http.StatusBadRequest
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	sendSuccess(w, nil, "Legal hold lifted")
}

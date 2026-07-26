// secret_schedule.go — temporal access schedule handlers.
//
// Routes (under /api/v1/secrets/{id}/schedule):
//
//	GET    /{id}/schedule — return the current schedule; 404 when none set
//	PUT    /{id}/schedule — set/replace the schedule; body: {allowed_days, start_hour, end_hour, timezone}
//	DELETE /{id}/schedule — remove the schedule (idempotent)
//
// All three routes require secrets.manage at the secret's project scope.
package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
)

// GetSecretSchedule handles GET /api/v1/secrets/{id}/schedule.
func (h *SecretHandler) GetSecretSchedule(w http.ResponseWriter, r *http.Request) {
	secretID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}
	sched, err := h.coreService.GetSecretSchedule(r.Context(), uint(secretID))
	if err != nil {
		log.Printf("GetSecretSchedule error for secret %d: %v", uint(secretID), err)
		h.sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	if sched == nil {
		h.sendError(w, "NotFound", "no schedule configured for this secret", http.StatusNotFound, nil)
		return
	}
	h.sendSuccess(w, sched, "")
}

// SetSecretSchedule handles PUT /api/v1/secrets/{id}/schedule.
func (h *SecretHandler) SetSecretSchedule(w http.ResponseWriter, r *http.Request) {
	secretID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}
	var body struct {
		AllowedDays string `json:"allowed_days"`
		StartHour   int    `json:"start_hour"`
		EndHour     int    `json:"end_hour"`
		Timezone    string `json:"timezone"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}
	if body.Timezone == "" {
		body.Timezone = "UTC"
	}
	sched, err := h.coreService.SetSecretSchedule(r.Context(), uint(secretID), body.AllowedDays, body.StartHour, body.EndHour, body.Timezone)
	if err != nil {
		status := http.StatusBadRequest
		if !isScheduleValidationError(err) {
			status = http.StatusInternalServerError
		}
		h.sendError(w, "Error", err.Error(), status, nil)
		return
	}
	h.sendSuccess(w, sched, "schedule set")
}

// DeleteSecretSchedule handles DELETE /api/v1/secrets/{id}/schedule.
func (h *SecretHandler) DeleteSecretSchedule(w http.ResponseWriter, r *http.Request) {
	secretID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.DeleteSecretSchedule(r.Context(), uint(secretID)); err != nil {
		log.Printf("DeleteSecretSchedule error for secret %d: %v", uint(secretID), err)
		h.sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	h.sendSuccess(w, map[string]bool{"deleted": true}, "schedule removed")
}

// isScheduleValidationError returns true when err originates from validateScheduleParams.
func isScheduleValidationError(err error) bool {
	return err != nil && !errors.Is(err, core.ErrAccessOutsideSchedule)
}

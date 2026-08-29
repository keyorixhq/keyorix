// break_glass.go — self-service emergency-access endpoints. Activation is NOT
// RBAC-gated (the point is access the caller does not have); the controls are
// config-enablement, a mandatory justification, loud audit, and auto-expiry. List
// and revoke ARE gated (roles.read / roles.assign) — they're review actions.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// ActivateBreakGlass handles POST /api/v1/projects/{id}/break-glass (self-service).
func (h *CatalogHandler) ActivateBreakGlass(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Justification string `json:"justification"`
		TTL           string `json:"ttl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if body.Justification == "" {
		sendError(w, "ValidationError", "justification is required", http.StatusBadRequest, nil)
		return
	}
	activation, err := h.coreService.ActivateBreakGlass(r.Context(), uint(id), actor.UserID, body.Justification, body.TTL)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, "permission denied"), strings.Contains(msg, "not enabled"):
			status = http.StatusForbidden
		case strings.Contains(msg, "required") || strings.Contains(msg, "ttl must") ||
			strings.Contains(msg, "no emergency role") || strings.Contains(msg, "not found"):
			status = http.StatusBadRequest
		default:
			log.Printf("Error activating break-glass for project %d: %v", id, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, map[string]interface{}{"activation": activation}, "Emergency access activated")
}

// ListBreakGlassActivations handles GET /api/v1/projects/{id}/break-glass.
func (h *CatalogHandler) ListBreakGlassActivations(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	activations, err := h.coreService.ListBreakGlassActivations(r.Context(), uint(id))
	if err != nil {
		log.Printf("Error listing break-glass activations for project %d: %v", id, err)
		sendError(w, "Error", clientSafe(err), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"activations": activations, "count": len(activations)}, "")
}

// RevokeBreakGlass handles POST /api/v1/projects/{id}/break-glass/{activationId}/revoke.
func (h *CatalogHandler) RevokeBreakGlass(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", errInvalidProjectID, http.StatusBadRequest, nil)
		return
	}
	activationID, err := strconv.ParseUint(chi.URLParam(r, "activationId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid activation ID", http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	if err := h.coreService.RevokeBreakGlass(r.Context(), actor.UserID, machineID(r), uint(id), uint(activationID)); err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, "not found"):
			status = http.StatusNotFound
		case strings.Contains(msg, "not active") || strings.Contains(msg, "required"):
			status = http.StatusBadRequest
		default:
			log.Printf("Error revoking break-glass activation %d for project %d: %v", activationID, id, err)
			msg = clientSafe(err)
		}
		sendError(w, "Error", msg, status, nil)
		return
	}
	sendSuccess(w, nil, "Emergency access revoked")
}

// machine_identities.go — machine identity endpoints (ADR-023).
//
// Non-human project members, segmented from human members in the Members view.
// Project-scoped: list is users.read; create/transition need roles.assign.
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ListMachineIdentities handles GET /api/v1/projects/{id}/machine-identities.
func (h *CatalogHandler) ListMachineIdentities(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	identities, err := h.coreService.ListMachineIdentities(r.Context(), uint(id))
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"machine_identities": identities}, "")
}

// CreateMachineIdentity handles POST /api/v1/projects/{id}/machine-identities.
func (h *CatalogHandler) CreateMachineIdentity(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Name         string `json:"name"`
		IdentityType string `json:"identity_type"`
		Description  string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	if body.Name == "" {
		sendError(w, "ValidationError", "name is required", http.StatusBadRequest, nil)
		return
	}
	m, err := h.coreService.CreateMachineIdentity(r.Context(), uint(id), body.Name, body.IdentityType, body.Description, actor.UserID)
	if err != nil {
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "invalid identity_type") || strings.Contains(err.Error(), "required") {
			status = http.StatusBadRequest
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	w.WriteHeader(http.StatusCreated)
	sendSuccess(w, map[string]interface{}{"machine_identity": m}, "Machine identity created")
}

// TransitionMachineIdentity handles PUT /api/v1/projects/{id}/machine-identities/{machineId}.
// Body: {"action": "activate" | "suspend" | "revoke"}.
func (h *CatalogHandler) TransitionMachineIdentity(w http.ResponseWriter, r *http.Request) {
	machineID, err := strconv.ParseUint(chi.URLParam(r, "machineId"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid machine identity ID", http.StatusBadRequest, nil)
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "InvalidJSON", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	to, ok := machineActionState(body.Action)
	if !ok {
		sendError(w, "ValidationError", "action must be activate, suspend, or revoke", http.StatusBadRequest, nil)
		return
	}
	m, err := h.coreService.TransitionMachineIdentity(r.Context(), uint(machineID), to, actor.UserID)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case strings.Contains(err.Error(), "not found"):
			status = http.StatusNotFound
		case strings.Contains(err.Error(), "cannot transition"):
			status = http.StatusConflict
		}
		sendError(w, "Error", err.Error(), status, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"machine_identity": m}, "Machine identity updated")
}

func machineActionState(action string) (string, bool) {
	switch action {
	case "activate":
		return core.MachineActive, true
	case "suspend":
		return core.MachineSuspended, true
	case "revoke":
		return core.MachineRevoked, true
	default:
		return "", false
	}
}

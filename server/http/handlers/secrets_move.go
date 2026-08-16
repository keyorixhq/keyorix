// secrets_move.go — MoveSecret handler: re-parent a secret or folder.
package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
)

// MoveSecret handles POST /api/v1/secrets/{id}/move
//
// Request body: { "parent_id": N }  — N=0 means move to root.
// Requires secrets.write at the secret's project scope (enforced by the route
// middleware); core re-checks write access via EnforceSecretWritePermission.
func (h *SecretHandler) MoveSecret(w http.ResponseWriter, r *http.Request) {
	userCtx, ok := mustGetUser(w, r)
	if !ok {
		return
	}

	secretID, ok := mustParseUintParam(w, r, "id", "InvalidParameter", errInvalidSecretID)
	if !ok {
		return
	}

	var reqBody struct {
		ParentID uint `json:"parent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", errInvalidJSON, http.StatusBadRequest, nil)
		return
	}

	// N=0 → root (nil parent); N>0 → pointer to that folder.
	var parentID *uint
	if reqBody.ParentID != 0 {
		pid := reqBody.ParentID
		parentID = &pid
	}

	updated, err := h.coreService.MoveSecret(r.Context(), userCtx.UserID, secretID, parentID)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, "not found"):
			status = http.StatusNotFound
		case strings.Contains(msg, "validation") ||
			strings.Contains(msg, "not a folder") ||
			strings.Contains(msg, "cannot move") ||
			strings.Contains(msg, "does not belong to the same project"):
			status = http.StatusBadRequest
		case strings.Contains(msg, "permission") || strings.Contains(msg, "not authorized"):
			status = http.StatusForbidden
		}
		h.sendError(w, "Error", msg, status, nil)
		return
	}
	h.sendSuccess(w, updated, "Secret moved")
}

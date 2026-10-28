// secrets_move.go — MoveSecret handler: re-parent a secret or folder.
package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
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
		case isSecretNotFound(err):
			status = http.StatusNotFound
		case errors.Is(err, core.ErrSecretInvalidInput):
			status = http.StatusBadRequest
		case isPermissionRefusal(err):
			status = http.StatusForbidden
		default:
			log.Printf("Error moving secret %d: %v", secretID, err) // NOSONAR
			msg = clientSafe(err)
		}
		h.sendError(w, "Error", msg, status, nil)
		return
	}
	h.sendSuccess(w, newSecretNodeWire(updated), "Secret moved")
}

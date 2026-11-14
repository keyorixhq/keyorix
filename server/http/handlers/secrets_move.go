// secrets_move.go — MoveSecret handler: re-parent a secret or folder.
package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/errclass"
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

	// The recorder tells a permission refusal core reached through a storage outage of
	// the permission lookup from a verdict (#3873).
	ctx, faults := core.WithAuthorizeFaultRecorder(r.Context())
	updated, err := h.coreService.MoveSecret(ctx, userCtx.UserID, secretID, parentID)
	if err != nil {
		answerCoreError(w, r, err, coreErrorAnswer{op: fmt.Sprintf("moving secret %d", secretID), faults: faults, texts: coreErrorTexts{
			errclass.NotFound:         err.Error(),
			errclass.PermissionDenied: err.Error(),
		}})
		return
	}
	h.sendSuccess(w, newSecretNodeWire(updated), "Secret moved")
}

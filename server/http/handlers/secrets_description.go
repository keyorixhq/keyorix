// secrets_description.go — DescribeSecret handler: set/clear a secret's free-text note.
package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/errclass"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// DescribeSecret handles PATCH /api/v1/secrets/{id}/description with {"description":"…"}
// — set or clear the secret's free-text note. Gated by secrets.write at the secret's
// scope (via the route middleware); core re-checks write access.
func (h *SecretHandler) DescribeSecret(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}
	var reqBody struct {
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	// The recorder tells a permission refusal core reached through a storage outage of
	// the permission lookup from a verdict (#3873).
	ctx, faults := core.WithAuthorizeFaultRecorder(r.Context())
	secret, err := h.coreService.SetSecretDescription(ctx, userCtx.UserID, uint(id), reqBody.Description)
	if err != nil {
		answerCoreError(w, r, err, coreErrorAnswer{op: fmt.Sprintf("describing secret %d", id), faults: faults, texts: coreErrorTexts{
			errclass.NotFound:         err.Error(),
			errclass.PermissionDenied: err.Error(),
		}})
		return
	}
	h.sendSuccess(w, newSecretNodeWire(secret), "Description updated")
}

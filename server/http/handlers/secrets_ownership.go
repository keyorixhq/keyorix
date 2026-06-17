// secrets_ownership.go — TransferOwnership handler: hand a secret's ownership to
// another user (the only principal that can manage/share it).
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// TransferOwnership handles POST /api/v1/secrets/{id}/transfer-ownership with body
// {"new_owner_id": N}. Scoped secrets.write is enforced by the router; the core layer
// then requires the caller to be the current owner (or the owner to be gone).
func (h *SecretHandler) TransferOwnership(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "BadRequest", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}
	var reqBody struct {
		NewOwnerID uint `json:"new_owner_id" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}
	if reqBody.NewOwnerID == 0 {
		h.sendError(w, "ValidationError", "new_owner_id is required", http.StatusBadRequest, nil)
		return
	}

	secret, err := h.coreService.TransferSecretOwnership(r.Context(), uint(id), reqBody.NewOwnerID, userCtx.UserID)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "not found"):
			h.sendError(w, "NotFound", err.Error(), http.StatusNotFound, nil)
		case strings.Contains(err.Error(), "only the current owner"):
			h.sendError(w, "Forbidden", "Only the current owner can transfer this secret", http.StatusForbidden, nil)
		case strings.Contains(err.Error(), "already owned"):
			h.sendError(w, "ValidationError", err.Error(), http.StatusBadRequest, nil)
		default:
			h.sendError(w, "InternalError", "Failed to transfer ownership", http.StatusInternalServerError, nil)
		}
		return
	}
	h.sendSuccess(w, secret, "Secret ownership transferred")
}

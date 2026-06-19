// secrets_description.go — DescribeSecret handler: set/clear a secret's free-text note.
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
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
	secret, err := h.coreService.SetSecretDescription(r.Context(), userCtx.UserID, uint(id), reqBody.Description)
	if err != nil {
		status := http.StatusInternalServerError
		msg := err.Error()
		switch {
		case strings.Contains(msg, "exceeds"):
			status = http.StatusBadRequest
		case strings.Contains(msg, "not found"):
			status = http.StatusNotFound
		case strings.Contains(msg, "permission") || strings.Contains(msg, "not authorized"):
			status = http.StatusForbidden
		}
		h.sendError(w, "Error", msg, status, nil)
		return
	}
	h.sendSuccess(w, secret, "Description updated")
}

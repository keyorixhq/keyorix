// rotation_dryrun.go — HTTP handler for POST /api/v1/secrets/{id}/rotation/simulate.
//
// The endpoint runs a dry-run (simulation) of the rotation configuration for a
// specific secret: it validates the policy, backend and ref without executing any
// live rotation. Requires secrets.read (read-only operation).
package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// SimulateRotation handles POST /api/v1/secrets/{id}/rotation/simulate
func (h *SecretHandler) SimulateRotation(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}

	result, err := h.coreService.SimulateRotation(r.Context(), core.RotationDryRunRequest{
		SecretID: uint(id),
	})
	if err != nil {
		if strings.Contains(err.Error(), "secret not found") {
			h.sendError(w, "NotFound", errSecretNotFound, http.StatusNotFound, nil)
			return
		}
		h.sendError(w, "InternalError", "Failed to simulate rotation", http.StatusInternalServerError, nil)
		return
	}

	h.sendSuccess(w, result, "")
}

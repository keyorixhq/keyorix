// blast_radius.go — GET /api/v1/secrets/{id}/blast-radius handler.
//
// Returns the full downstream dependency tree of a secret, enriched with
// OwnerID, ProjectID, and risk-level per dependent. Requires secrets.read.
package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// GetBlastRadius handles GET /api/v1/secrets/{id}/blast-radius
func (h *SecretHandler) GetBlastRadius(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}
	report, err := h.coreService.GetBlastRadius(r.Context(), uint(id))
	if err != nil {
		h.sendError(w, "Error", err.Error(), dependencyErrorStatus(err.Error()), nil)
		return
	}
	h.sendSuccess(w, report, "")
}

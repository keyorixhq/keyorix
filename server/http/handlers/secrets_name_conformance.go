// secrets_name_conformance.go — SecretNameConformance handler: a project's secrets whose
// names violate the CURRENT naming policy. The policy is enforced only at create time, so
// this surfaces names that fell out of conformance after the policy was added or tightened.
package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// SecretNameConformance handles GET /api/v1/projects/{id}/secrets/name-conformance — the
// project's live secrets whose names fail the current naming policy, each with the reason.
// Scoped secrets.read (project) is enforced by the router. Returns an empty (policy_enabled
// false) report when no naming policy is configured.
func (h *SecretHandler) SecretNameConformance(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "BadRequest", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}

	report, err := h.coreService.SecretNameConformance(r.Context(), uint(id))
	if err != nil {
		h.sendError(w, "InternalError", "Failed to evaluate naming-policy conformance", http.StatusInternalServerError, nil)
		return
	}
	h.sendSuccess(w, report, "")
}

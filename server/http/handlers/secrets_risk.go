// secrets_risk.go — per-secret risk-score handler.
//
// Route (under /api/v1/secrets):
//
//	GET /{id}/risk — composite risk score (expiry / rotation / usage / exposure)
package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// GetSecretRisk handles GET /api/v1/secrets/{id}/risk
func (h *SecretHandler) GetSecretRisk(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}

	risk, err := h.coreService.ComputeSecretRiskScore(r.Context(), uint(id))
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to compute secret risk", http.StatusInternalServerError, nil)
		}
		return
	}

	h.sendSuccess(w, risk, "")
}

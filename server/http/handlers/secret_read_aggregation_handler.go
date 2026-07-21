// secret_read_aggregation_handler.go — GET /api/v1/secrets/{id}/read-summary handler.
//
// Returns the top readers of a secret (by audit event count) over a configurable
// time window. Requires secrets.manage permission at the secret scope.
package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// GetSecretReadSummary handles GET /api/v1/secrets/{id}/read-summary
//
// Query parameters (all optional):
//
//	since  — RFC3339 start of the window (default: 30 days ago)
//	until  — RFC3339 end of the window (default: now)
//	limit  — max actors to return (default: 10, max: 50)
func (h *SecretHandler) GetSecretReadSummary(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}

	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", errInvalidSecretID, http.StatusBadRequest, nil)
		return
	}

	req := core.SecretReadSummaryRequest{
		SecretID: uint(id),
	}

	if v := r.URL.Query().Get("since"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			req.Since = t
		}
	}
	if v := r.URL.Query().Get("until"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			req.Until = t
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if l, err := strconv.Atoi(v); err == nil && l > 0 {
			req.Limit = l
		}
	}

	summary, err := h.coreService.GetSecretReadSummary(r.Context(), req)
	if err != nil {
		if errors.Is(err, core.ErrInvalidInput) {
			h.sendError(w, "InvalidParameter", err.Error(), http.StatusBadRequest, nil)
			return
		}
		h.sendError(w, "InternalServerError", "failed to retrieve read summary", http.StatusInternalServerError, nil)
		return
	}

	h.sendSuccess(w, summary, "")
}

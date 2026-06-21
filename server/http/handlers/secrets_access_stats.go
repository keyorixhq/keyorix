// secrets_access_stats.go — GetSecretAccessStats handler: per-secret read statistics
// (lifetime total + a recent-window summary), for a quick "is this secret used?" answer.
package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// GetSecretAccessStats handles GET /api/v1/secrets/{id}/stats?days=N — read statistics
// for the secret: lifetime total reads + reads / unique readers / last-read over the
// window (default 30 days, cap 365). Scoped secrets.read (enforced in core); no value.
func (h *SecretHandler) GetSecretAccessStats(w http.ResponseWriter, r *http.Request) {
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

	days := 0 // let core default to 30
	if v := r.URL.Query().Get("days"); v != "" {
		if n, perr := strconv.Atoi(v); perr == nil {
			days = n
		}
	}

	stats, err := h.coreService.GetSecretAccessStats(r.Context(), uint(id), userCtx.UserID, days)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "not found"):
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		case strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "not authorized"):
			h.sendError(w, "Forbidden", "Not authorized to view this secret", http.StatusForbidden, nil)
		default:
			h.sendError(w, "InternalError", "Failed to compute access stats", http.StatusInternalServerError, nil)
		}
		return
	}
	h.sendSuccess(w, stats, "")
}

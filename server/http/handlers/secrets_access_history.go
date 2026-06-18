// secrets_access_history.go — AccessHistory handler: recent reads of a secret.
package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// AccessHistory handles GET /api/v1/secrets/{id}/access-log?days=N — the secret's
// recent access-log entries (who read it, when, from where). Scoped secrets.read is
// enforced by the router; core re-checks the caller's read access. days defaults to
// 30 and is capped at 365.
func (h *SecretHandler) AccessHistory(w http.ResponseWriter, r *http.Request) {
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

	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		if n, perr := strconv.Atoi(v); perr == nil && n > 0 {
			days = n
		}
	}
	if days > 365 {
		days = 365
	}
	since := time.Now().AddDate(0, 0, -days)

	logs, err := h.coreService.ListSecretAccessHistory(r.Context(), uint(id), userCtx.UserID, since)
	if err != nil {
		switch {
		case strings.Contains(err.Error(), "not found"):
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		case strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "not authorized"):
			h.sendError(w, "Forbidden", "Not authorized to view this secret's access log", http.StatusForbidden, nil)
		default:
			h.sendError(w, "InternalError", "Failed to list access history", http.StatusInternalServerError, nil)
		}
		return
	}
	if logs == nil {
		logs = []models.SecretAccessLog{}
	}
	h.sendSuccess(w, map[string]interface{}{"access_log": logs, "total": len(logs)}, "")
}

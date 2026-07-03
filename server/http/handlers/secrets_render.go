// secrets_render.go — RenderTemplate handler: expand ${secret:env/name} references
// in a template using the caller's read access, scoped to one project.
package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// RenderTemplate handles POST /api/v1/projects/{id}/secrets/render — body
// {"template": "...${secret:production/db-password}..."} → {"rendered": "..."}.
// Read-only: it resolves references within the project the caller can read, per the
// per-secret permission check.
func (h *SecretHandler) RenderTemplate(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "BadRequest", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}
	var reqBody struct {
		Template string `json:"template"`
	}
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		h.sendError(w, "InvalidJSON", "Invalid JSON in request body", http.StatusBadRequest, nil)
		return
	}

	rendered, err := h.coreService.RenderSecretTemplate(r.Context(), reqBody.Template, uint(id), userCtx.UserID, userCtx.Username, r.RemoteAddr, r.Header.Get("User-Agent"))
	if err != nil {
		switch {
		// core.ErrSecretRefNotFound is returned uniformly for BOTH "no such secret" and
		// "secret exists but the caller can't read it" (see RenderSecretTemplate) — a
		// project viewer must not be able to tell those apart via 404-vs-403 (#181), so
		// this one case owns both and must be checked before the generic "not found" /
		// "permission" substring branches below.
		case errors.Is(err, core.ErrSecretRefNotFound):
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		case strings.Contains(err.Error(), "not found"):
			h.sendError(w, "NotFound", err.Error(), http.StatusNotFound, nil)
		case strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "not authorized"):
			h.sendError(w, "Forbidden", "Not authorized to read a referenced secret", http.StatusForbidden, nil)
		case strings.Contains(err.Error(), "invalid reference"), strings.Contains(err.Error(), "unterminated"),
			strings.Contains(err.Error(), "empty secret reference"),
			strings.Contains(err.Error(), "cannot be safely substituted"):
			h.sendError(w, "ValidationError", err.Error(), http.StatusBadRequest, nil)
		default:
			h.sendError(w, "InternalError", "Failed to render template", http.StatusInternalServerError, nil)
		}
		return
	}

	h.sendSuccess(w, map[string]interface{}{"rendered": rendered}, "")
}

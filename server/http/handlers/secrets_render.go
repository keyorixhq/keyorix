// secrets_render.go — RenderTemplate handler: expand ${secret:env/name} references
// in a template using the caller's read access, scoped to one project.
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
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
		case strings.Contains(err.Error(), "not found"):
			h.sendError(w, "NotFound", err.Error(), http.StatusNotFound, nil)
		case strings.Contains(err.Error(), "permission") || strings.Contains(err.Error(), "not authorized"):
			h.sendError(w, "Forbidden", "Not authorized to read a referenced secret", http.StatusForbidden, nil)
		case strings.Contains(err.Error(), "invalid reference"), strings.Contains(err.Error(), "unterminated"),
			strings.Contains(err.Error(), "empty secret reference"):
			h.sendError(w, "ValidationError", err.Error(), http.StatusBadRequest, nil)
		default:
			h.sendError(w, "InternalError", "Failed to render template", http.StatusInternalServerError, nil)
		}
		return
	}

	h.sendSuccess(w, map[string]interface{}{"rendered": rendered}, "")
}

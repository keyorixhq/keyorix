// projects_suspend.go — project-wide suspend/resume: freeze or restore value reads of
// every secret in a project (incident response).
package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// SuspendProjectSecrets handles POST /api/v1/projects/{id}/secrets/suspend-all with an
// optional {"reason": "..."}. Scoped secrets.write (project) is enforced by the router.
func (h *SecretHandler) SuspendProjectSecrets(w http.ResponseWriter, r *http.Request) {
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
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&reqBody) // optional

	n, err := h.coreService.SuspendProjectSecrets(r.Context(), uint(id), userCtx.UserID, reqBody.Reason)
	if err != nil {
		h.sendError(w, "InternalError", "Failed to suspend project secrets", http.StatusInternalServerError, nil)
		return
	}
	h.sendSuccess(w, map[string]interface{}{"suspended": n}, "")
}

// ResumeProjectSecrets handles POST /api/v1/projects/{id}/secrets/resume-all.
func (h *SecretHandler) ResumeProjectSecrets(w http.ResponseWriter, r *http.Request) {
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
	n, err := h.coreService.ResumeProjectSecrets(r.Context(), uint(id), userCtx.UserID)
	if err != nil {
		h.sendError(w, "InternalError", "Failed to resume project secrets", http.StatusInternalServerError, nil)
		return
	}
	h.sendSuccess(w, map[string]interface{}{"resumed": n}, "")
}

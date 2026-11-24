// secrets_bulk_delete.go — BulkDeleteSecrets handler: delete multiple secrets in
// one call. Scoped secrets.delete (project) is enforced by the router and again
// by core (#4666).
// Each deletion calls the same DeleteSecret logic as the single-delete path
// (audit log, dependency events, etc.) so no cleanup is bypassed.
package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// BulkDeleteSecrets handles POST /api/v1/projects/{id}/secrets/bulk-delete with
// {"secret_ids":[1,2,3]}. Each ID is deleted via the normal single-secret delete
// path; partial success is allowed — failures are collected in the response rather
// than aborting the entire batch.
func (h *SecretHandler) BulkDeleteSecrets(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "BadRequest", "Invalid project ID", http.StatusBadRequest, nil)
		return
	}

	var req core.BulkDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	ip, ua := clientIP(r), r.Header.Get("User-Agent")
	// Tagged, so each item commits its secret.deleted row in its own transaction and an
	// audit-log outage fails that item, changing nothing, with code audit_unavailable
	// (retryable) instead of the delete committing with a best-effort row.
	result, err := h.coreService.BulkDeleteSecrets(secretMutationAuditContext(r, userCtx), req, uint(projectID), userCtx.Username, userCtx.UserID, ip, ua)
	if err != nil {
		// Core's own project gate (#4666): a refusal is a 403 and a failed read of
		// the actor's roles a 503, as for bulk-rotate, never a server error.
		if sendStorageUnavailable(w, err) {
			return
		}
		if errors.Is(err, core.ErrPermissionDenied) {
			h.sendError(w, "Forbidden", errorMessageFor(http.StatusForbidden, err), http.StatusForbidden, nil)
			return
		}
		status := http.StatusInternalServerError
		if strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "exceeds the maximum batch size") {
			status = http.StatusBadRequest
		}
		h.sendError(w, "Error", errorMessageFor(status, err), status, nil)
		return
	}

	// The summary says how many failures are outages that the same call can repeat
	// (#3912); the per-item code/retryable fields say which.
	msg := ""
	if result.Retryable > 0 {
		msg = fmt.Sprintf("%d of %d secrets were not deleted because the service was unavailable; retry them", result.Retryable, result.Total)
	}
	h.sendSuccess(w, result, msg)
}

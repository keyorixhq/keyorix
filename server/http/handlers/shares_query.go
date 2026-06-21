// shares_query.go — List and status query handlers.
//
// ListSecretShares, ListShares, ListSharedSecrets,
// GetSharingStatusWithIndicators, RemoveSelfFromShare.
// For share create/update/revoke see shares_crud.go.
package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ListSecretShares handles GET /api/v1/secrets/{id}/shares
func (h *ShareHandler) ListSecretShares(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}

	// The route already enforces scoped secrets.read on this secret
	// (RequireScopedPermission in the router), so listing its shares is already
	// access-gated here.
	shares, err := h.coreService.ListSecretShares(r.Context(), uint(id))
	if err != nil {
		log.Printf("Error listing secret shares: %v", err)
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to list secret shares", http.StatusInternalServerError, nil)
		}
		return
	}

	h.sendSuccess(w, map[string]interface{}{"shares": shares}, "")
}

// ListShares handles GET /api/v1/shares — returns the caller's shares (received +
// owned) as a paginated list of enriched views (recipient/creator names resolved,
// expiry included). Supports ?secretId= and ?recipientType=user|group filters and
// ?page / ?pageSize paging. The response shape matches the web client's
// PaginatedResponse (camelCase), which consumes it without field mapping.
func (h *ShareHandler) ListShares(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	views, err := h.coreService.ListUserShareViews(r.Context(), userCtx.UserID)
	if err != nil {
		log.Printf("Error listing shares: %v", err)
		h.sendError(w, "InternalError", "Failed to list shares", http.StatusInternalServerError, nil)
		return
	}

	// Optional server-side filters.
	if v := r.URL.Query().Get("secretId"); v != "" {
		if sid, perr := strconv.ParseUint(v, 10, 32); perr == nil {
			views = filterShareViews(views, func(s core.ShareView) bool { return s.SecretID == uint(sid) })
		}
	}
	if rt := r.URL.Query().Get("recipientType"); rt == "user" || rt == "group" {
		views = filterShareViews(views, func(s core.ShareView) bool { return s.RecipientType == rt })
	}

	page := atoiDefault(r.URL.Query().Get("page"), 1)
	pageSize := atoiDefault(r.URL.Query().Get("pageSize"), 20)
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 200 {
		pageSize = 20
	}

	total := len(views)
	totalPages := (total + pageSize - 1) / pageSize
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	pageItems := views[start:end]
	if pageItems == nil {
		pageItems = []core.ShareView{}
	}

	h.sendSuccess(w, map[string]interface{}{
		"data":       pageItems,
		"total":      total,
		"page":       page,
		"pageSize":   pageSize,
		"totalPages": totalPages,
	}, "")
}

// filterShareViews returns the views satisfying keep.
func filterShareViews(views []core.ShareView, keep func(core.ShareView) bool) []core.ShareView {
	out := views[:0:0]
	for _, v := range views {
		if keep(v) {
			out = append(out, v)
		}
	}
	return out
}

// atoiDefault parses s as an int, returning def on empty/invalid input.
func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// ListSharedSecrets handles GET /api/v1/shared-secrets
func (h *ShareHandler) ListSharedSecrets(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	secrets, err := h.coreService.ListSharedSecrets(r.Context(), userCtx.UserID)
	if err != nil {
		log.Printf("Error listing shared secrets: %v", err)
		h.sendError(w, "InternalError", "Failed to list shared secrets", http.StatusInternalServerError, nil)
		return
	}
	if secrets == nil {
		secrets = []*models.SecretNode{}
	}

	h.sendSuccess(w, map[string]interface{}{"secrets": secrets}, "")
}

// ListGroupSharedSecrets handles GET /api/v1/groups/{id}/shared-secrets — the live
// secrets currently shared with a group (the "what can this group reach" view).
func (h *ShareHandler) ListGroupSharedSecrets(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	groupID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid group ID", http.StatusBadRequest, nil)
		return
	}

	secrets, err := h.coreService.ListGroupSharedSecrets(r.Context(), uint(groupID))
	if err != nil {
		log.Printf("Error listing group shared secrets: %v", err)
		h.sendError(w, "InternalError", "Failed to list group shared secrets", http.StatusInternalServerError, nil)
		return
	}
	if secrets == nil {
		secrets = []*models.SecretNode{}
	}

	h.sendSuccess(w, map[string]interface{}{"secrets": secrets}, "")
}

// GetSharingStatusWithIndicators handles GET /api/v1/secrets/{id}/sharing-status
func (h *ShareHandler) GetSharingStatusWithIndicators(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}

	status, err := h.coreService.GetSecretSharingStatusWithIndicators(r.Context(), uint(id), userCtx.UserID)
	if err != nil {
		log.Printf("Error getting sharing status: %v", err)
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Secret not found", http.StatusNotFound, nil)
		} else if strings.Contains(err.Error(), "permission") {
			h.sendError(w, "Forbidden", "Access denied", http.StatusForbidden, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to get sharing status", http.StatusInternalServerError, nil)
		}
		return
	}

	h.sendSuccess(w, status, "")
}

// RemoveSelfFromShare handles DELETE /api/v1/secrets/{id}/self-share
func (h *ShareHandler) RemoveSelfFromShare(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		h.sendError(w, "InvalidParameter", "Invalid secret ID", http.StatusBadRequest, nil)
		return
	}

	if err := h.coreService.RemoveSelfFromShare(r.Context(), uint(id), userCtx.UserID); err != nil {
		log.Printf("Error removing self from share: %v", err)
		if strings.Contains(err.Error(), "not found") {
			h.sendError(w, "NotFound", "Share not found", http.StatusNotFound, nil)
		} else {
			h.sendError(w, "InternalError", "Failed to remove self from share", http.StatusInternalServerError, nil)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

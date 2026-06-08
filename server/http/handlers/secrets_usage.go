// secrets_usage.go — usage-analytics handlers (most-accessed / unused secrets).
//
// Routes (under /api/v1/secrets):
//
//	GET /usage/most-accessed — top secrets by read count (params: project_id, days, limit)
//	GET /usage/unused        — secrets not read in N days, never-read first (params: project_id, days)
package handlers

import (
	"net/http"
	"strconv"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// parseProjectIDQuery reads an optional project_id query param. Returns
// (nil, true) when absent, (ptr, true) when valid, (nil, false) when malformed.
func parseProjectIDQuery(r *http.Request) (*uint, bool) {
	v := r.URL.Query().Get("project_id")
	if v == "" {
		return nil, true
	}
	id, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		return nil, false
	}
	uid := uint(id)
	return &uid, true
}

// parseIntQuery reads an optional positive int query param, falling back to def.
func parseIntQuery(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// UsageMostAccessed handles GET /api/v1/secrets/usage/most-accessed
func (h *SecretHandler) UsageMostAccessed(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	projectID, ok := parseProjectIDQuery(r)
	if !ok {
		h.sendError(w, "InvalidParameter", "Invalid project_id", http.StatusBadRequest, nil)
		return
	}
	days := parseIntQuery(r, "days", 30)
	limit := parseIntQuery(r, "limit", 10)

	stats, err := h.coreService.MostAccessedSecrets(r.Context(), projectID, days, limit)
	if err != nil {
		h.sendError(w, "InternalError", "Failed to compute most-accessed secrets", http.StatusInternalServerError, nil)
		return
	}

	h.sendSuccess(w, map[string]interface{}{"secrets": stats, "days": days}, "")
}

// UsageUnused handles GET /api/v1/secrets/usage/unused
func (h *SecretHandler) UsageUnused(w http.ResponseWriter, r *http.Request) {
	if middleware.GetUserFromContext(r.Context()) == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	projectID, ok := parseProjectIDQuery(r)
	if !ok {
		h.sendError(w, "InvalidParameter", "Invalid project_id", http.StatusBadRequest, nil)
		return
	}
	days := parseIntQuery(r, "days", 30)

	stats, err := h.coreService.UnusedSecrets(r.Context(), projectID, days)
	if err != nil {
		h.sendError(w, "InternalError", "Failed to compute unused secrets", http.StatusInternalServerError, nil)
		return
	}

	h.sendSuccess(w, map[string]interface{}{"secrets": stats, "days": days}, "")
}

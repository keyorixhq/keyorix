// secrets_list.go — ListSecrets handler.
//
// Handles GET /api/v1/secrets with filtering, pagination, and sharing info.
// For CRUD operations see secrets_crud.go.
package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ListSecrets handles GET /api/v1/secrets
func (h *SecretHandler) ListSecrets(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	page := 1
	pageSize := 20

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	filter := &models.SecretListFilter{
		Page:      page,
		PageSize:  pageSize,
		SortBy:    r.URL.Query().Get("sort_by"),
		SortOrder: r.URL.Query().Get("sort_order"),
	}

	if r.URL.Query().Get("show_owned_only") == "true" {
		filter.ShowOwnedOnly = true
	}
	if r.URL.Query().Get("show_shared_only") == "true" {
		filter.ShowSharedOnly = true
	}
	if permission := r.URL.Query().Get("permission"); permission != "" {
		filter.Permission = permission
	}
	if typeParam := strings.TrimSpace(r.URL.Query().Get("type")); typeParam != "" {
		filter.Type = &typeParam
	}
	if namespaceStr := r.URL.Query().Get("namespace_id"); namespaceStr != "" {
		if nsID, err := strconv.ParseUint(namespaceStr, 10, 32); err == nil {
			nsIDUint := uint(nsID)
			filter.NamespaceID = &nsIDUint
		}
	}
	if zoneStr := r.URL.Query().Get("zone_id"); zoneStr != "" {
		if zID, err := strconv.ParseUint(zoneStr, 10, 32); err == nil {
			zIDUint := uint(zID)
			filter.ZoneID = &zIDUint
		}
	}
	if envStr := r.URL.Query().Get("environment_id"); envStr != "" {
		if eID, err := strconv.ParseUint(envStr, 10, 32); err == nil {
			eIDUint := uint(eID)
			filter.EnvironmentID = &eIDUint
		}
	}

	response, err := h.coreService.ListSecretsWithSharingInfo(r.Context(), userCtx.UserID, filter)
	if err != nil {
		log.Printf("Error listing secrets: %v", err)
		h.sendError(w, "InternalError", "Failed to list secrets", http.StatusInternalServerError, nil)
		return
	}

	h.resolveSecretNames(r.Context(), response.Secrets)
	h.sendSuccess(w, response, "")
}

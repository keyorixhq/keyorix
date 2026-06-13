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
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ListSecrets handles GET /api/v1/secrets.
//
// Scope enforcement happens in the RequireScopedPermission middleware against
// the project_id/environment_id query params: a non-global reader must narrow
// the request to a project/environment they can read, and that same filter then
// bounds the rows returned here. Global readers (and admins) may list unscoped.
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
	if pageSizeStr := r.URL.Query().Get("pageSize"); pageSizeStr != "" {
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

	if search := strings.TrimSpace(r.URL.Query().Get("search")); search != "" {
		filter.Search = &search
	}

	if r.URL.Query().Get("include_deleted") == "true" {
		filter.IncludeDeleted = true
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
	if projectStr := r.URL.Query().Get("project_id"); projectStr != "" {
		if pID, err := strconv.ParseUint(projectStr, 10, 32); err == nil {
			pIDUint := uint(pID)
			filter.ProjectID = &pIDUint
		}
	}
	if envStr := r.URL.Query().Get("environment_id"); envStr != "" {
		if eID, err := strconv.ParseUint(envStr, 10, 32); err == nil {
			eIDUint := uint(eID)
			filter.EnvironmentID = &eIDUint
		}
	}
	if eb := r.URL.Query().Get("expires_before"); eb != "" {
		if t, err := time.Parse(time.RFC3339, eb); err == nil {
			filter.ExpiresBefore = &t
		}
	}

	// Machine principals (ADR-030) have no user identity for the owned/shared
	// model; they list by their authorized scope (already gated by the route).
	var response *models.SecretListResponse
	var err error
	if userCtx.MachineIdentityID != nil {
		response, err = h.coreService.ListSecretsInScope(r.Context(), filter)
	} else {
		response, err = h.coreService.ListSecretsWithSharingInfo(r.Context(), userCtx.UserID, filter)
	}
	if err != nil {
		log.Printf("Error listing secrets: %v", err)
		h.sendError(w, "InternalError", "Failed to list secrets", http.StatusInternalServerError, nil)
		return
	}

	h.resolveSecretNames(r.Context(), response.Secrets)
	h.sendSuccess(w, response, "")
}

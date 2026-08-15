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

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// ListSecrets handles GET /api/v1/secrets.
//
// Authorization is performed inside this handler (the route carries NO
// RequireScopedPermission middleware for this endpoint) so that project-scoped
// readers — who lack a global secrets.read grant — get the union of all secrets
// they can read across their accessible project/environment scopes rather than
// a blanket 403.
//
// Decision tree:
//  1. If a specific project_id or environment_id filter is in the query, call
//     ListSecretsWithSharingInfo directly — it returns owned + ACL-granted
//     secrets within the requested scope. Users with no project role but
//     per-secret ACL grants see exactly their granted secrets; users with
//     neither see an empty list. No 403 is returned for scoped queries.
//  2. If no scope filter is given, check for a global (Scope{}) grant first.
//     Global readers proceed normally (original behaviour).
//  3. If neither check passes, enumerate every scope where the user holds
//     secrets.read, fetch secrets for each, union them (deduplicated by ID),
//     and return the merged page. A user with NO role scopes calls
//     ListSecretsWithSharingInfo without a scope filter so that their owned
//     and ACL-granted secrets are still surfaced.
//  4. Machine principals skip steps 2–3 and always use ListSecretsInScope
//     (machines have no user ownership model and are already gated by their
//     own role assignments).
func (h *SecretHandler) ListSecrets(w http.ResponseWriter, r *http.Request) { // NOSONAR -- cognitive complexity 41, suppress go:S3776
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		h.sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}

	page := 1
	pageSize := 20

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			// Clamp the page so a very large value can't force a huge OFFSET scan over the
			// whole table on every request (deep-pagination DoS).
			if p > maxListPage {
				p = maxListPage
			}
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
	if cls := strings.TrimSpace(r.URL.Query().Get("classification")); cls != "" {
		// Data-classification filter (ISO A.5.12); "unclassified" matches secrets
		// with no label (handled in the storage layer).
		filter.Classification = &cls
	}
	// Tag filter: repeatable ?tag=a&tag=b or a single comma-separated ?tag=a,b.
	// A secret must carry every requested tag (AND).
	for _, raw := range r.URL.Query()["tag"] {
		for part := range strings.SplitSeq(raw, ",") {
			if t := strings.TrimSpace(part); t != "" {
				filter.Tags = append(filter.Tags, t)
			}
		}
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
	if pidStr := r.URL.Query().Get("parent_id"); pidStr != "" {
		if pID, err := strconv.ParseUint(pidStr, 10, 32); err == nil {
			pIDUint := uint(pID)
			filter.ParentID = &pIDUint
		}
	}
	if r.URL.Query().Get("folder_only") == "true" {
		filter.FolderOnly = true
	}

	// Machine principals (ADR-030) have no user identity for the owned/shared
	// model; they list by their authorized scope without the scoped-union logic.
	// Security gate (CWE-862): a machine token must supply an explicit project_id
	// and must be authorized for secrets.read within that project. Without this
	// gate, any machine token (regardless of its assigned project scope) could
	// enumerate secrets from arbitrary projects or across all projects.
	var response *models.SecretListResponse
	var err error
	if userCtx.MachineIdentityID != nil {
		if filter.ProjectID == nil {
			h.sendError(w, "BadRequest", "machine tokens must specify project_id", http.StatusBadRequest, nil)
			return
		}
		scope := core.Scope{ProjectID: *filter.ProjectID}
		if filter.EnvironmentID != nil {
			scope.EnvironmentID = *filter.EnvironmentID
		}
		allowed, aerr := h.coreService.AuthorizePrincipal(
			r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), permSecretsRead, scope,
		)
		if aerr != nil || !allowed {
			h.sendError(w, "Forbidden", "Insufficient permissions", http.StatusForbidden, nil)
			return
		}
		response, err = h.coreService.ListSecretsInScope(r.Context(), filter)
		if err != nil {
			log.Printf("Error listing secrets: %v", err)
			h.sendError(w, "InternalError", errFailedToListSecrets, http.StatusInternalServerError, nil)
			return
		}
		h.resolveSecretNames(r.Context(), response.Secrets)
		h.sendSuccess(w, response, "")
		return
	}

	// Human principal path — authorization is performed here (the route has no
	// RequireScopedPermission middleware for this endpoint).
	requestedScope := core.Scope{}
	if filter.ProjectID != nil {
		requestedScope.ProjectID = *filter.ProjectID
	}
	if filter.EnvironmentID != nil {
		requestedScope.EnvironmentID = *filter.EnvironmentID
	}

	scopeRequested := requestedScope.ProjectID != 0 || requestedScope.EnvironmentID != 0

	if scopeRequested {
		// Scoped listing. Two visibility tiers, no hard 403 in either case (a
		// blanket 403 here would block an ACL-only principal who holds a
		// valid per-secret grant in the requested scope but no project role):
		//
		//  - Role-authorized for this exact scope: surface every secret the
		//    ROLE grants visibility to, not just what this user personally
		//    owns or holds an ACL/share grant for. Matches what per-secret
		//    GET endpoints already grant via RequireScopedPermission --
		//    without this, a project-scoped viewer role could read any
		//    individual secret in their project but never discover it via
		//    listing.
		//  - Otherwise: owned secrets + ACL-granted secrets only (unchanged
		//    prior behavior), so ACL-only users still see their grants and
		//    users with no access at all see an empty list.
		scopeOK, aerr := h.coreService.AuthorizePrincipal(
			r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), permSecretsRead, requestedScope,
		)
		if aerr == nil && scopeOK {
			response, err = h.coreService.ListSecretsInScopeWithSharingInfo(r.Context(), userCtx.UserID, filter)
		} else {
			response, err = h.coreService.ListSecretsWithSharingInfo(r.Context(), userCtx.UserID, filter)
		}
		if err != nil {
			log.Printf("Error listing secrets: %v", err)
			h.sendError(w, "InternalError", errFailedToListSecrets, http.StatusInternalServerError, nil)
			return
		}
		h.resolveSecretNames(r.Context(), response.Secrets)
		h.sendSuccess(w, response, "")
		return
	}

	// No scope filter — try global first.
	globalOK, aerr := h.coreService.AuthorizePrincipal(
		r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), permSecretsRead, core.Scope{},
	)
	if aerr == nil && globalOK {
		// Global reader — original behaviour.
		response, err = h.coreService.ListSecretsWithSharingInfo(r.Context(), userCtx.UserID, filter)
		if err != nil {
			log.Printf("Error listing secrets: %v", err)
			h.sendError(w, "InternalError", errFailedToListSecrets, http.StatusInternalServerError, nil)
			return
		}
		h.resolveSecretNames(r.Context(), response.Secrets)
		h.sendSuccess(w, response, "")
		return
	}

	// Not a global reader — enumerate scopes and return the union.
	scopes, serr := h.coreService.GetReadableScopes(r.Context(), userCtx.PrincipalID(), permSecretsRead)
	if serr != nil {
		log.Printf("Error enumerating readable scopes for user %d: %v", userCtx.UserID, serr)
		h.sendError(w, "InternalError", errFailedToListSecrets, http.StatusInternalServerError, nil)
		return
	}

	if len(scopes) == 0 {
		// No project-role scopes, but the user may still hold per-secret ACL
		// grants or own secrets directly.  Call ListSecretsWithSharingInfo with
		// no scope filter so owned + ACL-granted secrets are surfaced.
		response, err = h.coreService.ListSecretsWithSharingInfo(r.Context(), userCtx.UserID, filter)
		if err != nil {
			log.Printf("Error listing secrets for ACL-only user %d: %v", userCtx.UserID, err)
			h.sendError(w, "InternalError", errFailedToListSecrets, http.StatusInternalServerError, nil)
			return
		}
		h.resolveSecretNames(r.Context(), response.Secrets)
		h.sendSuccess(w, response, "")
		return
	}

	log.Printf("ListSecrets: user %d has no global secrets.read; returning union across %d scope(s)", userCtx.UserID, len(scopes))

	seen := make(map[uint]bool)
	var allSecrets []*models.SecretWithSharingInfo
	for _, scope := range scopes {
		scopeFilter := *filter // shallow copy — safe: slice fields (Tags) are read-only here
		pID := scope.ProjectID
		scopeFilter.ProjectID = &pID
		if scope.EnvironmentID != 0 {
			eID := scope.EnvironmentID
			scopeFilter.EnvironmentID = &eID
		} else {
			scopeFilter.EnvironmentID = nil
		}
		// scopes are already known role-granted scopes (from GetReadableScopes
		// above), so this surfaces every secret each scope's role grants
		// visibility to -- not just what the user personally owns or holds an
		// ACL/share grant for -- same reasoning as the scopeRequested branch
		// above.
		resp, rerr := h.coreService.ListSecretsInScopeWithSharingInfo(r.Context(), userCtx.UserID, &scopeFilter)
		if rerr != nil {
			log.Printf("Error listing secrets for scope {project:%d env:%d}: %v", scope.ProjectID, scope.EnvironmentID, rerr)
			continue
		}
		for _, s := range resp.Secrets {
			if s.SecretNode != nil && !seen[s.ID] {
				seen[s.ID] = true
				allSecrets = append(allSecrets, s)
			}
		}
	}

	// Re-apply sorting and paginate the merged result.
	total := int64(len(allSecrets))
	start := (filter.Page - 1) * filter.PageSize
	end := start + filter.PageSize
	totalInt := int(total)
	if start > totalInt {
		start = totalInt
	}
	if end > totalInt {
		end = totalInt
	}
	totalPages := (totalInt + filter.PageSize - 1) / filter.PageSize
	if totalPages == 0 {
		totalPages = 1
	}
	pagedSecrets := allSecrets[start:end]

	response = &models.SecretListResponse{
		Secrets:    pagedSecrets,
		Total:      total,
		Page:       filter.Page,
		PageSize:   filter.PageSize,
		TotalPages: totalPages,
	}
	h.resolveSecretNames(r.Context(), response.Secrets)
	h.sendSuccess(w, response, "")
}

// secret_readable_listing.go — "which secrets can this human caller read", with no
// scope filter supplied.
//
// This is the decision tree that used to live only inside
// server/http/handlers/secrets_list.go's ListSecrets handler. It is here because
// TWO callers need the same answer and must not be allowed to disagree about it:
//
//   - GET /api/v1/secrets — the list the user sees;
//   - the dashboard's TOTAL SECRETS tile (#2780) — which is supposed to be the
//     count OF that list.
//
// Before #2780 the dashboard counted something else entirely — secrets the caller
// had AUTHORED (`SecretFilter{CreatedBy: &username}`) — so a project member who had
// created nothing was told "TOTAL SECRETS 0 … Create your first secret to get
// started" while reading five. Re-deriving the same tree in a second place is
// exactly how #2781's two-definitions bug happened, so the tree moved here and both
// callers go through it; the count is `resp.Total` from literally the same code that
// produced the list.
//
// Scope: the HUMAN, no-scope-filter path only. The handler keeps its own branches
// for a machine principal (ADR-030: machines must name an explicit project_id and
// have no ownership model) and for an explicitly scoped request
// (?project_id/?environment_id), because both of those decisions depend on the
// request in ways the dashboard has no analogue for. Those branches are unchanged.
package core

import (
	"context"
	"fmt"
	"log"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListReadableSecrets returns the secrets userID can read when NO project or
// environment filter was supplied, in three tiers, mirroring the per-secret GET
// endpoints' own authorization:
//
//  1. A caller holding secrets.read at the GLOBAL scope gets
//     ListSecretsWithSharingInfo's ordinary answer (unchanged original behaviour).
//  2. Otherwise, every scope where the caller holds secrets.read is enumerated and
//     the per-scope results are unioned, deduplicated by secret ID, then re-paged.
//     This is what makes a project-scoped reader able to DISCOVER the secrets their
//     role already lets them GET one at a time.
//  3. A caller with no role-granted scope at all still goes through
//     ListSecretsWithSharingInfo unfiltered, so secrets they own or hold a
//     per-secret ACL/share grant for are surfaced. A caller with none of those gets
//     an empty list — never a 403, which is the whole point.
//
// filter must not carry a ProjectID or EnvironmentID; those are the handler's
// scoped branch, not this one. Page/PageSize are honoured (and defaulted if unset).
//
// principalID is the caller's RBAC identity — the machine identity ID for a machine
// token, otherwise the same as userID. The authorization calls use it;
// ownership/sharing resolution uses userID, exactly as before.
//
// # Two defects fixed while extracting this
//
// Both were in the handler's tier-2 union loop and both were found by reading the
// code being moved, not by a failing test:
//
//  1. Each scope was fetched at the CALLER's page size and the results then merged
//     and re-paged. With pageSize=20 and three scopes of 25 secrets each, the union
//     saw at most 20 per scope, so the response reported Total=60 for a caller who
//     could read 75 — a silently wrong count, and page 4 did not exist. Each scope
//     is now fetched at full width (maxUnionPageSize) and only the MERGED set is
//     paged, which is the only order that can produce a correct total.
//  2. The comment said "Re-apply sorting and paginate the merged result" and then
//     only paginated: each scope arrived individually sorted and the concatenation
//     was not re-sorted, so ?sort_by came out interleaved by scope. sortSecrets now
//     actually runs on the merged set, as the comment always claimed.
func (c *KeyorixCore) ListReadableSecrets(ctx context.Context, userID, principalID uint, filter *models.SecretListFilter) (*models.SecretListResponse, error) {
	if filter == nil {
		filter = &models.SecretListFilter{}
	}
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PageSize < 1 {
		filter.PageSize = 20
	}
	actorType := actorTypeFromContext(ctx)

	// Tier 1 — global reader.
	globalOK, aerr := c.AuthorizePrincipal(ctx, actorType, principalID, permSecretsRead, Scope{})
	if aerr == nil && globalOK {
		return c.ListSecretsWithSharingInfo(ctx, userID, filter)
	}

	scopes, serr := c.GetReadableScopes(ctx, principalID, permSecretsRead)
	if serr != nil {
		return nil, fmt.Errorf("list readable secrets: enumerate readable scopes: %w", serr)
	}

	// Tier 3 — no role-granted scope, but possibly owned or ACL/share-granted
	// secrets. Checked before the union loop because the union loop over zero scopes
	// would return an empty list and hide them.
	if len(scopes) == 0 {
		return c.ListSecretsWithSharingInfo(ctx, userID, filter)
	}

	// Tier 2 — union across every readable scope.
	seen := make(map[uint]bool)
	var all []*models.SecretWithSharingInfo
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
		// Paginate each scope at full width, not at the caller's page size: the
		// per-scope results are MERGED and re-paged below, so a scope truncated to
		// one page here would silently drop rows from the union (and from the total).
		scopeFilter.Page = 1
		scopeFilter.PageSize = maxUnionPageSize
		// These are already known role-granted scopes, so surface everything the
		// ROLE grants visibility to -- not just what the user personally owns or
		// holds an ACL/share grant for.
		resp, rerr := c.ListSecretsInScopeWithSharingInfo(ctx, userID, &scopeFilter)
		if rerr != nil {
			// Best-effort per scope, matching the handler's prior behaviour: one
			// unreadable scope must not blank the whole list. Logged, because a
			// persistently failing scope would otherwise look like an empty one.
			log.Printf("ListReadableSecrets: listing scope {project:%d env:%d} failed, skipping: %v",
				scope.ProjectID, scope.EnvironmentID, rerr)
			continue
		}
		for _, s := range resp.Secrets {
			if s.SecretNode != nil && !seen[s.ID] {
				seen[s.ID] = true
				all = append(all, s)
			}
		}
	}

	c.sortSecrets(all, filter.SortBy, filter.SortOrder)
	return pageSecrets(all, filter.Page, filter.PageSize), nil
}

// maxUnionPageSize is the per-scope page width used while building the union above.
// It is deliberately large rather than unbounded: the merge holds every row in
// memory, so a pathological scope should be truncated loudly-in-the-logs rather
// than exhaust the process. It is far above any realistic per-scope secret count.
const maxUnionPageSize = 100000

// pageSecrets slices all into one page and reports the full total, so a caller can
// tell "page 1 of many" from "that is everything".
func pageSecrets(all []*models.SecretWithSharingInfo, page, pageSize int) *models.SecretListResponse {
	total := int64(len(all))
	totalInt := len(all)
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > totalInt {
		start = totalInt
	}
	if end > totalInt {
		end = totalInt
	}
	totalPages := (totalInt + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	return &models.SecretListResponse{
		Secrets:    all[start:end],
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}
}

// CountReadableSecrets is ListReadableSecrets' total, which is what the dashboard's
// TOTAL SECRETS tile reports (#2780). It asks for one row rather than a full page so
// a large deployment does not serialize every secret to produce a number — the total
// is computed over the whole set either way.
//
// There is deliberately no separate counting query: a count derived independently of
// the listing is a second definition waiting to diverge, which is precisely the
// defect this function exists to fix.
func (c *KeyorixCore) CountReadableSecrets(ctx context.Context, userID, principalID uint) (int64, error) {
	resp, err := c.ListReadableSecrets(ctx, userID, principalID, &models.SecretListFilter{Page: 1, PageSize: 1})
	if err != nil {
		return 0, err
	}
	return resp.Total, nil
}

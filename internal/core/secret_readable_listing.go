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
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListReadableSecrets returns the secrets userID can read when NO project or
// environment filter was supplied, in three tiers, mirroring the per-secret GET
// endpoints' own authorization:
//
//  1. A caller holding secrets.read at the GLOBAL scope gets EVERY secret, with
//     sharing metadata attached — because that is what the grant authorizes.
//  2. Otherwise, every scope where the caller holds secrets.read is enumerated and
//     the per-scope results are unioned, deduplicated by secret ID, then re-paged.
//     This is what makes a project-scoped reader able to DISCOVER the secrets their
//     role already lets them GET one at a time.
//  3. A caller with no role-granted scope at all goes through
//     ListSecretsWithSharingInfo unfiltered, so secrets they own or hold a
//     per-secret ACL/share grant for are surfaced. A caller with none of those gets
//     an empty list — never a 403, which is the whole point.
//
// Tiers 1 and 2 are "what the ROLE makes visible"; tier 3 is "what this USER
// personally owns or was granted". That split is the one thing to preserve when
// editing this function: widening tier 3 would hand an ACL-only caller the whole
// deployment, and narrowing tiers 1/2 back to the tier-3 set is precisely the bug
// described below.
//
// filter must not carry a ProjectID or EnvironmentID; those are the handler's
// scoped branch, not this one. Page/PageSize are honoured (and defaulted if unset).
//
// principalID is the caller's RBAC identity — the machine identity ID for a machine
// token, otherwise the same as userID. The authorization calls use it;
// ownership/sharing resolution uses userID, exactly as before.
//
// # Defects fixed here, and how each was found
//
// Recorded with provenance because the pattern matters: all four are the same shape —
// a count or a list that was quietly short — and only one of them was ever caught by
// a test.
//
//  1. (tier 2, found by reading the code being moved) Each scope was fetched at the
//     CALLER's page size and the results then merged and re-paged. With pageSize=20
//     and three scopes of 25 secrets each, the union saw at most 20 per scope, so the
//     response reported Total=60 for a caller who could read 75 — and page 4 did not
//     exist. Each scope is now fetched at full width and only the MERGED set is
//     paged, which is the only order that can produce a correct total.
//  2. (tier 2, found the same way) The comment said "Re-apply sorting and paginate
//     the merged result" and then only paginated, so ?sort_by came out interleaved by
//     scope. sortSecrets now actually runs on the merged set.
//  3. (tier 1, found by REVIEW of #2859 — no test caught it) Tier 1 delegated to
//     ListSecretsWithSharingInfo, the owned ∪ shared ∪ ACL-granted set, so a global
//     secrets.read holder who owned nothing saw an EMPTY list while authorized to
//     read everything. #2859's own e2e equality assertion passed over it, because
//     that fixture's admin had created every secret and therefore owned them all —
//     both sides of the equality were wrong by the same amount. See
//     secret_readable_listing_global_test.go, whose fixture gives the global reader
//     ownership of nothing precisely so the two definitions can be told apart.
//  4. (tier 2, found by REVIEW) maxUnionPageSize's truncation was silent, although
//     its own comment claimed it would be loud. It now logs and sets
//     SecretListResponse.Truncated, and CountReadableSecrets reports the count as
//     non-exact so GetDashboardStats degrades instead of showing a floor as a count.
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

	// Tier 1 — global reader: everything, because that is what the grant authorizes.
	//
	// This used to call ListSecretsWithSharingInfo, which is owned ∪ shared ∪
	// ACL-granted — a DIFFERENT set, and an empty one for a global reader who owns
	// nothing. So a caller authorized to read every secret in the deployment saw an
	// empty list while being able to GET any of those secrets individually. That is
	// #2780's defect one tier up, and it survived the move into this file because the
	// tier was preserved verbatim as "unchanged original behaviour" — the comment was
	// accurate and the behaviour was still wrong.
	//
	// ListSecretsInScopeWithSharingInfo with NO scope filter is the right call: it
	// surfaces every secret the grant makes visible AND attaches the per-secret
	// ownership/share/ACL metadata the UI renders. It is the same function tiers 2
	// uses per scope, so a global reader is now the degenerate case of the scoped
	// reader rather than a separate code path with separate semantics.
	//
	// Not a disclosure change: the caller holds secrets.read at Scope{}, which
	// authorizes every project, and RequireScopedSecretPermission already serves them
	// any individual secret. Same narrowing-vs-consistency argument as #2780 — the
	// listing is being made consistent with what is already readable.
	globalOK, aerr := c.AuthorizePrincipal(ctx, actorType, principalID, permSecretsRead, Scope{})
	if aerr == nil && globalOK {
		return c.ListSecretsInScopeWithSharingInfo(ctx, userID, filter)
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
	//
	// Worth knowing, and pre-existing on main rather than introduced here: a tier-2
	// caller gets ONLY the union of their role-granted scopes. A secret they own,
	// or hold an ACL/share grant for, that lies OUTSIDE those scopes appears in
	// neither this list nor its count — while remaining individually GETtable,
	// because RequireScopedSecretPermission honours the per-secret grant. That is
	// the same listing-vs-item inconsistency as the four defects this file exists to
	// close, one tier along, and tier 3 does not have it (it returns exactly the
	// owned ∪ shared ∪ ACL set). Closing it would mean merging the tier-3 personal
	// set into the tier-2 union, which is a visibility change rather than a
	// consistency fix, so it is recorded here instead of made silently.
	seen := make(map[uint]bool)
	var all []*models.SecretWithSharingInfo
	var truncatedScopes []string
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
		scopeFilter.PageSize = c.unionPageSize()
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
		// maxUnionPageSize is a real bound, so say so when it bites. resp.Total is
		// the scope's full count; len(resp.Secrets) is what this page actually
		// carried. The old code's comment claimed truncation would be
		// "loudly-in-the-logs" and nothing logged, and the response carried no
		// signal — a silently short Total, which is the same class of defect as
		// #2780's confidently-wrong zero.
		// resp.Truncated is the signal that matters at the shipped configuration:
		// the storage clamp (listingMaxRows) cuts the scope BEFORE it is paged, so
		// the page is full and Total == len(Secrets) even when the scope was cut.
		// The Total comparison only catches a union page size below the storage
		// clamp (i.e. tests).
		if resp.Truncated || resp.Total > int64(len(resp.Secrets)) {
			log.Printf("ListReadableSecrets: scope {project:%d env:%d} holds %d secrets but the union is bounded at %d — "+
				"the merged total is a FLOOR, not a count (principal_id=%d)",
				scope.ProjectID, scope.EnvironmentID, resp.Total, c.unionPageSize(), principalID)
			truncatedScopes = append(truncatedScopes,
				fmt.Sprintf("project %d environment %d (%d secrets)", scope.ProjectID, scope.EnvironmentID, resp.Total))
		}
		for _, s := range resp.Secrets {
			if s.SecretNode != nil && !seen[s.ID] {
				seen[s.ID] = true
				all = append(all, s)
			}
		}
	}

	c.sortSecrets(all, filter.SortBy, filter.SortOrder)
	out := pageSecrets(all, filter.Page, filter.PageSize)
	if len(truncatedScopes) > 0 {
		out.Truncated = true
		out.TruncatedReason = fmt.Sprintf("per-scope listing bounded at %d secrets; affected: %s",
			c.unionPageSize(), strings.Join(truncatedScopes, "; "))
	}
	return out, nil
}

// maxUnionPageSize is the per-scope page width used while building the union above.
// It is deliberately large rather than unbounded: the merge holds every row in
// memory, so a pathological scope should be truncated loudly rather than exhaust
// the process.
//
// It is NOT the effective cap, and saying otherwise is what hid F1. The storage
// layer bounds each query at secretListingMaxRows (10000, secret_listing_query.go),
// so this 100000 is shadowed: a scope is clamped to 10000 rows long before this
// number is reached. Both bounds now report truncation — this one per scope in the
// union loop above, the storage one inside listSecretsInScopeRows — but only the
// storage bound can actually bite in production. An earlier version of this comment
// called 100000 "far above any realistic per-scope secret count", which was true
// and irrelevant.
const maxUnionPageSize = 100000

// unionPageSize returns the per-scope page width to use. It exists so a test can
// drive the truncation path at a realistic fixture size instead of seeding 100001
// secrets — a bound that can only be exercised by an unaffordable fixture is a bound
// nobody has watched behave, which is how its truncation came to be silent in the
// first place (defect 4 above).
//
// Production always takes maxUnionPageSize: the override is unexported, defaults to
// 0, and is set only by tests in this package. (An earlier version of this comment
// said "via t.Cleanup-restored assignment"; none of the five call sites used
// t.Cleanup. That is harmless — each test builds its own KeyorixCore from
// readableListingFixture, so there is no shared value to restore — but the comment
// described a discipline that was not being followed, which is worse than
// describing none. Coordinator review of #2874, F5.)
func (c *KeyorixCore) unionPageSize() int {
	if c.unionPageSizeOverride > 0 {
		return c.unionPageSizeOverride
	}
	return maxUnionPageSize
}

// errUnexactReadableSecretCount is the reason GetDashboardStats records when
// CountReadableSecrets reports a non-exact total. A sentinel rather than an inline
// string so the degrade reason is identical wherever it is raised.
var errUnexactReadableSecretCount = errors.New(
	"the readable-secret listing hit its per-scope bound, so this total is a floor rather than a count")

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
//
// The second return value is `exact`: false means the listing hit its per-scope bound
// and the number is a FLOOR. The caller must not present a non-exact count as a
// count — GetDashboardStats flips DashboardStats.Degraded, which is the mechanism
// that already exists for "this zero/number is unknown, not verified". Returning the
// flag rather than swallowing it is the point: a silently short count is the defect
// class, not an acceptable approximation.
func (c *KeyorixCore) CountReadableSecrets(ctx context.Context, userID, principalID uint) (total int64, exact bool, err error) {
	resp, err := c.ListReadableSecrets(ctx, userID, principalID, &models.SecretListFilter{Page: 1, PageSize: 1})
	if err != nil {
		return 0, false, err
	}
	return resp.Total, !resp.Truncated, nil
}

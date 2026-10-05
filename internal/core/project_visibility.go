// project_visibility.go — "which projects may this caller READ".
//
// This is a PERMISSION question, and it is deliberately not the same question as
// "is this caller a member of project P" (project_membership_definition.go). The
// answer here is a strict superset of membership: a caller holding `secrets.read`
// at the global scope can read every project while being a member of none, and a
// caller whose only grants are project-scoped can read exactly those projects.
//
// Conflating the two would break in both directions — answering a project LISTING
// from membership hides every project from a global admin, and answering a
// membership check from readability hands project data to a non-member — so they
// live in separate files with separate names.
//
// # Why this exists (#2780)
//
// `GET /api/v1/projects` and `GET /api/v1/environments` used to be gated on GLOBAL
// `secrets.read` and then return EVERY project, unfiltered. For the ordinary
// least-privilege shape — `system_viewer` globally plus `project_viewer` on one
// project, which is what a developer handed access to one service holds — that is
// a 403, even though the same account can read that project's 5 secrets through
// `GET /api/v1/secrets` and read the project itself through
// `GET /api/v1/projects/{id}`. The consequence in the UI was not a 403 page: the
// project switcher came up empty, `/projects` rendered an empty list, the New
// Secret dialog's required Project/Environment selects had nothing to select, and
// the call fires from the layout, so the persona took a 403 on every route in the
// app. The CLI paid for it too, with a whole numeric-ID-only fallback
// (`cli/cmd/project_resolve.go`'s `resolveProjectScoped`).
//
// The fix narrows rather than widens: list the projects the caller can ALREADY
// read, under the same per-scope authorization the per-project routes enforce. No
// caller gains sight of a project they could not already `GET` by id — a global
// reader's list is unchanged, and a caller with no grants gets an empty list
// instead of a 403.
//
// `ListSecrets` (server/http/handlers/secrets_list.go) has worked this way since it
// was written, and its doc comment makes this exact argument; #2780 is that
// argument not yet applied to the project and environment listings.
package core

import (
	"context"
	"fmt"
	"log"
)

// ProjectVisibility is the answer to "which projects may this caller read".
//
// All is true when the caller holds the permission at the GLOBAL scope, which
// authorizes every project including ones created after this call — so a caller
// with All must not be filtered against IDs (there is no finite ID set to filter
// against, and materialising one would silently drop a project created between the
// enumeration and the response).
//
// When All is false, IDs is the exact, possibly-empty set of project IDs the caller
// may read. An empty set is a legitimate answer, not an error: a caller with no
// project grants can read no project, and should see an empty list rather than a
// 403 (a 403 is what made the UI report "you have nothing", which is worse).
type ProjectVisibility struct {
	All bool
	IDs map[uint]struct{}
}

// Allows reports whether projectID is visible under this answer.
func (v ProjectVisibility) Allows(projectID uint) bool {
	if v.All {
		return true
	}
	_, ok := v.IDs[projectID]
	return ok
}

// Empty reports whether the caller may read no project at all. Only meaningful
// when All is false.
func (v ProjectVisibility) Empty() bool { return !v.All && len(v.IDs) == 0 }

// VisibleProjects resolves which projects the principal may read with permission.
//
// It asks the global scope first (one authorization call, and the common case for
// an admin-tier caller), then falls back to enumerating the principal's
// project-scoped grants via GetReadableScopes — which is machine-identity aware
// (G33), honours a PAT's own project narrowing, and fails closed per scope.
//
// This performs the authorization; it does NOT fetch or filter any project. The
// caller applies the result, so one visibility answer can gate several listings
// (projects and their environments) without re-authorizing.
//
// Fails closed: on a storage error the answer is "nothing visible" alongside the
// error, never "everything".
func (c *KeyorixCore) VisibleProjects(ctx context.Context, actorType string, principalID uint, permission string) (ProjectVisibility, error) {
	global, err := c.AuthorizePrincipal(ctx, actorType, principalID, permission, Scope{})
	if err != nil {
		return ProjectVisibility{}, fmt.Errorf("visible projects: global authorization check: %w", err)
	}
	if global {
		return ProjectVisibility{All: true}, nil
	}

	scopes, err := c.GetReadableScopes(ctx, principalID, permission)
	if err != nil {
		return ProjectVisibility{}, fmt.Errorf("visible projects: enumerate readable scopes: %w", err)
	}
	candidates := make(map[uint]struct{}, len(scopes))
	for _, s := range scopes {
		if s.ProjectID == 0 {
			continue // GetReadableScopes already skips the global scope; belt and braces.
		}
		candidates[s.ProjectID] = struct{}{}
	}

	// The decisive check, and the reason this second pass exists: a project is
	// visible only if the caller is authorized at the PROJECT scope
	// (environment_id = 0) — which is exactly what `GET /api/v1/projects/{id}`
	// requires. GetReadableScopes also returns ENVIRONMENT-scoped grants, and an
	// environment-scoped grant does NOT authorize the project scope:
	// GetUserRoleIDsAt matches `environment_id = 0 OR environment_id = <asked>`, so a
	// grant at (project P, environment E) fails a check at (project P, environment 0).
	// Such a caller genuinely cannot read project P by id today, so listing P for them
	// would be new disclosure, not a consistency fix. Re-checking at the project scope
	// makes "every row in this list is a row the caller can already GET by id" true by
	// construction rather than by argument.
	ids := make(map[uint]struct{}, len(candidates))
	for pid := range candidates {
		ok, aerr := c.AuthorizePrincipal(ctx, actorType, principalID, permission, Scope{ProjectID: pid})
		if aerr != nil {
			// Fail closed for this project, and log it: a persistently failing check
			// would otherwise be indistinguishable from a caller who is legitimately
			// ungranted there (same reasoning as GetReadableScopes' own skip).
			log.Printf("VisibleProjects: project-scope authorization check failed, skipping project (actor_type=%s principal_id=%d permission=%s project_id=%d): %v",
				actorType, principalID, permission, pid, aerr)
			continue
		}
		if ok {
			ids[pid] = struct{}{}
		}
	}
	return ProjectVisibility{IDs: ids}, nil
}

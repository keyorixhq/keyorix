// permission_baseline.go — GetPermissionBaseline: export every user's effective
// permissions (through roles + group membership) as a flat edge list.
// Used for auditor hand-off (CSV / JSON) via the compliance endpoints.
//
// #G25: this function used to independently reassemble grant data (its own
// user lookup, its own scope label, its own "include everything" grant reads)
// instead of building on the same raw grant shape the canonical resolver
// (authz.go's scopedRoleIDs, GetUserRoleIDsAt/GetUserGroupRoleIDsAt) already
// gets right. That ad hoc assembly had three independent correctness gaps,
// all fixed here:
//
//  1. A soft-deleted user's grant rows are NOT cascade-deleted when the
//     account is deleted — only the user's own deleted_at is set. The old
//     code fetched users with the DEFAULT (live-only) filter, so a
//     soft-deleted grant holder's row was silently absent from userByID and
//     every grant referencing them was dropped with no trace. Now ListUsers
//     is called with IncludeDeleted: true and each row carries a
//     HolderDeleted flag instead of vanishing.
//  2. Expired time-bound (JIT) grants were always included (by design — this
//     is a historical compliance snapshot, not a live-access view) but
//     nothing distinguished them from a currently-authorizing grant. Now each
//     row carries GrantExpired.
//  3. Group-inherited grants were reported at a hardcoded "global" scope
//     regardless of the group_roles row's actual project/environment — and
//     even direct grants only encoded ProjectID, silently dropping an
//     environment-scoped grant's real (narrower) reach. scopeLabel now takes
//     both ProjectID and EnvironmentID for every grant, direct or
//     group-inherited.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// PermissionBaselineRow is one user→role→permission edge in the deployment,
// annotated with the scope at which the role was granted.
type PermissionBaselineRow struct {
	UserID     uint   `json:"user_id"`
	Username   string `json:"username"`
	Email      string `json:"email"`
	RoleName   string `json:"role_name"`
	Scope      string `json:"scope"` // "global", "project:<id>", or "project:<id>/environment:<id>"
	Permission string `json:"permission"`
	// GrantExpired is true when this grant's ExpiresAt has already passed. The
	// row stays in the export either way — an auditor needs the full grant
	// history, not just what's live right now — but callers that want only
	// currently-authorizing grants can now filter on this instead of having no
	// way to tell a lapsed grant from a live one (#G25).
	GrantExpired bool `json:"grant_expired"`
	// HolderDeleted is true when the user holding this grant has since been
	// soft-deleted. Deleting a user does not cascade-delete their role grant
	// rows, so the grant itself still exists in storage; this row now surfaces
	// it (flagged) instead of silently disappearing from the export (#G25).
	HolderDeleted bool `json:"holder_deleted"`
}

// PermissionBaseline is the full permission edge list for the deployment.
type PermissionBaseline struct {
	GeneratedAt time.Time               `json:"generated_at"`
	Rows        []PermissionBaselineRow `json:"rows"`
}

// permBaselineBuilder holds the shared caches used during a GetPermissionBaseline call.
type permBaselineBuilder struct {
	k             *KeyorixCore
	rolePermCache map[uint][]string
	roleNameCache map[uint]string
}

// rolePermNames returns the permission names for roleID, caching the result.
func (b *permBaselineBuilder) rolePermNames(ctx context.Context, roleID uint) ([]string, error) {
	if names, ok := b.rolePermCache[roleID]; ok {
		return names, nil
	}
	perms, err := b.k.storage.GetRolePermissions(ctx, roleID)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(perms))
	for _, p := range perms {
		names = append(names, p.Name)
	}
	b.rolePermCache[roleID] = names
	return names, nil
}

// roleName returns the name of roleID, caching the result.
func (b *permBaselineBuilder) roleName(ctx context.Context, roleID uint) (string, error) {
	if name, ok := b.roleNameCache[roleID]; ok {
		return name, nil
	}
	role, err := b.k.storage.GetRole(ctx, roleID)
	if err != nil {
		return "", err
	}
	b.roleNameCache[roleID] = role.Name
	return role.Name, nil
}

// userBaseline is a compact struct for the fields we carry per-user in the
// builder for direct grants (keyed by userID, since a UserRole grant row only
// carries the ID, not the full user record).
type userBaseline struct {
	username string
	email    string
	// deleted mirrors models.User.DeletedAt.Valid — see PermissionBaselineRow.HolderDeleted.
	deleted bool
}

// directGrantRows appends rows for direct user→role grants. allGrants is the
// UNFILTERED grant set (ListAllUserRoleGrants) — live, expired, and held by a
// soft-deleted user alike; userByID (built from a ListUsers call with
// IncludeDeleted: true) resolves every one of those holders, including
// soft-deleted ones, so only a grant referencing a truly nonexistent user ID
// (never a merely soft-deleted one) is skipped.
func (b *permBaselineBuilder) directGrantRows(ctx context.Context, allGrants []*models.UserRole, userByID map[uint]*userBaseline, now time.Time) ([]PermissionBaselineRow, error) {
	var rows []PermissionBaselineRow
	for _, grant := range allGrants {
		u, ok := userByID[grant.UserID]
		if !ok {
			continue // no user row at all, even including soft-deleted — a genuinely orphaned grant
		}
		name, err := b.roleName(ctx, grant.RoleID)
		if err != nil {
			return nil, fmt.Errorf("permission baseline: get role %d: %w", grant.RoleID, err)
		}
		perms, err := b.rolePermNames(ctx, grant.RoleID)
		if err != nil {
			return nil, fmt.Errorf("permission baseline: get permissions for role %d: %w", grant.RoleID, err)
		}
		scope := scopeLabel(grant.ProjectID, grant.EnvironmentID)
		expired := grantExpired(grant.ExpiresAt, now)
		for _, perm := range perms {
			rows = append(rows, PermissionBaselineRow{
				UserID:        grant.UserID,
				Username:      u.username,
				Email:         u.email,
				RoleName:      name,
				Scope:         scope,
				Permission:    perm,
				GrantExpired:  expired,
				HolderDeleted: u.deleted,
			})
		}
	}
	return rows, nil
}

// groupGrantRowsForUser appends rows for group-inherited grants for one user.
// groupGrantsByGroup is the whole deployment's group_roles table (
// ListAllGroupRoleGrants), pre-grouped by GroupID, so each grant's real scope
// and expiry ride along instead of the caller re-deriving them — the fix for
// #G25's scope-misrepresentation and missing-expiry-flag gaps on the
// group-inherited path specifically (GetGroupRoles alone carries neither).
func (b *permBaselineBuilder) groupGrantRowsForUser(ctx context.Context, u *models.User, groupGrantsByGroup map[uint][]*models.GroupRole, now time.Time) ([]PermissionBaselineRow, error) {
	var rows []PermissionBaselineRow
	groups, err := b.k.storage.GetUserGroups(ctx, u.ID)
	if err != nil {
		return nil, fmt.Errorf("permission baseline: get groups for user %d: %w", u.ID, err)
	}
	for _, g := range groups {
		for _, grant := range groupGrantsByGroup[g.ID] {
			name, err := b.roleName(ctx, grant.RoleID)
			if err != nil {
				return nil, fmt.Errorf("permission baseline: get role %d (group %d): %w", grant.RoleID, g.ID, err)
			}
			perms, err := b.rolePermNames(ctx, grant.RoleID)
			if err != nil {
				return nil, fmt.Errorf("permission baseline: get permissions for role %d (group %d): %w", grant.RoleID, g.ID, err)
			}
			scope := scopeLabel(grant.ProjectID, grant.EnvironmentID)
			expired := grantExpired(grant.ExpiresAt, now)
			for _, perm := range perms {
				rows = append(rows, PermissionBaselineRow{
					UserID:        u.ID,
					Username:      u.Username,
					Email:         u.Email,
					RoleName:      name,
					Scope:         scope,
					Permission:    perm,
					GrantExpired:  expired,
					HolderDeleted: u.DeletedAt.Valid,
				})
			}
		}
	}
	return rows, nil
}

// GetPermissionBaseline returns every user→role→permission edge in the system,
// expanding through both direct UserRole grants and GroupRole grants (via
// UserGroup→Group→GroupRole). Each distinct (user, role, scope, permission)
// tuple becomes one PermissionBaselineRow. Expired grants are included (snapshot
// of all grants, including time-bound ones) so the auditor sees the full history —
// flagged via GrantExpired, not silently indistinguishable from a live grant.
// Soft-deleted grant holders are included too, flagged via HolderDeleted, rather
// than dropped. Each row's Scope reflects the grant's real (project, environment)
// pair, not just its project.
//
// #G44: groupGrantRowsForUser below still runs one GetUserGroups call PER
// USER — a genuine N+1 whose cost scales with the deployment's own user
// count, not with any caller-controlled input. Fixing #G25's scope/expiry gap
// replaced the FORMER per-GROUP GetGroupRoles call with one deployment-wide
// ListAllGroupRoleGrants query below, but the per-user group-MEMBERSHIP
// lookup remains. Unlike this group's other members, there's no bound to add
// here that wouldn't just silently drop users from a compliance/audit report;
// the real fix is restructuring to batch-load every user's group membership in
// one or two queries up front. Left unfixed — see REMEDIATION-STATUS.md G44.
func (k *KeyorixCore) GetPermissionBaseline(ctx context.Context) (*PermissionBaseline, error) {
	// 1. Load all users, INCLUDING soft-deleted ones (no filter otherwise — we
	//    want every principal that ever held a grant). See the #G25 doc above:
	//    soft-deleting a user does not cascade-delete their role grants.
	users, _, err := k.storage.ListUsers(ctx, &storage.UserFilter{PageSize: 100000, IncludeDeleted: true})
	if err != nil {
		return nil, fmt.Errorf("permission baseline: list users: %w", err)
	}

	// 2. Load all direct and group role grants in one shot each — the whole
	//    deployment's user_roles and group_roles tables, unfiltered (live,
	//    expired, any scope). This is the same raw grant shape the canonical
	//    resolver (authz.go's scopedRoleIDs) reads before IT filters down to a
	//    single scope's live grants; this function keeps the unfiltered,
	//    full-history view (an audit snapshot, not a live-access check) but now
	//    carries each grant's real scope and expiry through to the row.
	allGrants, err := k.storage.ListAllUserRoleGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("permission baseline: list user role grants: %w", err)
	}
	allGroupGrants, err := k.storage.ListAllGroupRoleGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("permission baseline: list group role grants: %w", err)
	}
	groupGrantsByGroup := make(map[uint][]*models.GroupRole, len(allGroupGrants))
	for _, g := range allGroupGrants {
		groupGrantsByGroup[g.GroupID] = append(groupGrantsByGroup[g.GroupID], g)
	}

	// Build quick lookup map (direct-grant path only — the group-inherited path
	// already has the full *models.User in hand from `users`).
	userByID := make(map[uint]*userBaseline, len(users))
	for _, u := range users {
		userByID[u.ID] = &userBaseline{username: u.Username, email: u.Email, deleted: u.DeletedAt.Valid}
	}

	now := k.now()
	b := &permBaselineBuilder{
		k:             k,
		rolePermCache: make(map[uint][]string),
		roleNameCache: make(map[uint]string),
	}

	// 3. Direct user→role grants.
	rows, err := b.directGrantRows(ctx, allGrants, userByID, now)
	if err != nil {
		return nil, err
	}

	// 4. Group-inherited grants.
	for _, u := range users {
		groupRows, err := b.groupGrantRowsForUser(ctx, u, groupGrantsByGroup, now)
		if err != nil {
			return nil, err
		}
		rows = append(rows, groupRows...)
	}

	if rows == nil {
		rows = []PermissionBaselineRow{}
	}
	return &PermissionBaseline{
		GeneratedAt: now.UTC(),
		Rows:        rows,
	}, nil
}

// scopeLabel renders a grant's (project, environment) scope into the string
// form stored in the CSV/JSON: "global" when project is the 0 sentinel,
// "project:<id>" for a project-wide grant, and "project:<id>/environment:<id>"
// for a grant scoped down to one environment within that project. The
// project-only form previously used for EVERY grant (direct or
// group-inherited) reported an environment-scoped grant as applying to the
// whole project — overstating its real reach (#G25).
func scopeLabel(projectID, environmentID uint) string {
	if projectID == 0 {
		return "global"
	}
	if environmentID == 0 {
		return fmt.Sprintf("project:%d", projectID)
	}
	return fmt.Sprintf("project:%d/environment:%d", projectID, environmentID)
}

// grantExpired mirrors shareActive's expiry rule (permissions.go): a nil
// ExpiresAt is permanent (never expired); otherwise the grant is expired once
// now is no longer strictly before it — the same instant authorization queries
// (GetUserRoleIDsAt et al.) stop treating the grant as live.
func grantExpired(expiresAt *time.Time, now time.Time) bool {
	return expiresAt != nil && !now.Before(*expiresAt)
}

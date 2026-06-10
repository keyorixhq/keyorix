// authz.go — Scope-aware permission enforcement (RBAC Phase 2).
//
// Authorize is the single entrypoint the HTTP middleware uses to decide whether
// a user may perform an action against a particular project/environment. It
// resolves the roles that apply at the target scope — both directly assigned and
// inherited via group membership — then checks whether any of them grants the
// permission. A user holding the admin (or super_admin) role at, or above, the
// target scope bypasses the specific-permission check: the super-user escape
// hatch. All resolution errors fail closed (deny).
package core

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// Scope identifies the project/environment an authorization check or a role
// assignment applies to. It aliases storage.Scope so the same 0 = global
// sentinel flows from the HTTP layer through to the queries unchanged.
type Scope = storage.Scope

// adminRoleNames are roles that bypass the per-permission check at the scope
// they are assigned. A global (project 0) admin therefore bypasses everywhere;
// a project-scoped admin bypasses only within that project.
//
// "admin"/"super_admin" are the legacy single-tier super-users; "system_admin"
// and "project_admin" are the ADR-021 two-tier equivalents. A system_admin is
// expected to be assigned globally (bypasses install-wide); a project_admin is
// expected to be assigned at a project scope (bypasses within that project).
var adminRoleNames = []string{"super_admin", "admin", "system_admin", "project_admin"}

// AuthorizePrincipal reports whether a principal — a human user or a machine
// identity (ADR-030) — may exercise permission against the target scope. It is
// the actor-aware entrypoint the auth gates use; Authorize is the user-only
// wrapper kept for source compatibility. Machine principals resolve their
// permissions from machine_identity_roles and receive NO admin-role bypass: a
// machine is never a global super-user, so a leaked machine token is bounded to
// the permissions of its explicit grants. Fails closed.
func (c *KeyorixCore) AuthorizePrincipal(ctx context.Context, actorType string, principalID uint, permission string, scope Scope) (bool, error) {
	if actorType == ActorTypeMachine {
		roleIDs, err := c.storage.GetMachineRoleIDsAt(ctx, principalID, scope)
		if err != nil {
			return false, err
		}
		if len(roleIDs) == 0 {
			return false, nil
		}
		return c.storage.RoleSetHasPermission(ctx, roleIDs, permission)
	}
	return c.Authorize(ctx, principalID, permission, scope)
}

// Authorize reports whether userID may exercise permission (e.g. "secrets.read")
// against the target scope. Fails closed: any resolution error returns
// (false, err).
func (c *KeyorixCore) Authorize(ctx context.Context, userID uint, permission string, scope Scope) (bool, error) {
	roleIDs, err := c.scopedRoleIDs(ctx, userID, scope)
	if err != nil {
		return false, err
	}
	if len(roleIDs) == 0 {
		return false, nil
	}
	if c.roleSetContainsAdmin(ctx, roleIDs) {
		return true, nil
	}
	return c.storage.RoleSetHasPermission(ctx, roleIDs, permission)
}

// IsGlobalAdmin reports whether userID holds an admin role assigned globally
// (project 0, environment 0). Used to short-circuit scope-filtered listing.
func (c *KeyorixCore) IsGlobalAdmin(ctx context.Context, userID uint) (bool, error) {
	roleIDs, err := c.scopedRoleIDs(ctx, userID, Scope{})
	if err != nil {
		return false, err
	}
	return c.roleSetContainsAdmin(ctx, roleIDs), nil
}

// scopedRoleIDs returns the de-duplicated set of role IDs that apply to userID
// at the target scope, unioning direct assignments and group-inherited roles.
func (c *KeyorixCore) scopedRoleIDs(ctx context.Context, userID uint, scope Scope) ([]uint, error) {
	direct, err := c.storage.GetUserRoleIDsAt(ctx, userID, scope)
	if err != nil {
		return nil, err
	}
	viaGroups, err := c.storage.GetUserGroupRoleIDsAt(ctx, userID, scope)
	if err != nil {
		return nil, err
	}
	return dedupeUints(append(direct, viaGroups...)), nil
}

// roleSetContainsAdmin reports whether any role ID in the set is an admin role.
func (c *KeyorixCore) roleSetContainsAdmin(ctx context.Context, roleIDs []uint) bool {
	if len(roleIDs) == 0 {
		return false
	}
	idSet := make(map[uint]struct{}, len(roleIDs))
	for _, id := range roleIDs {
		idSet[id] = struct{}{}
	}
	for _, name := range adminRoleNames {
		role, err := c.storage.GetRoleByName(ctx, name)
		if err != nil {
			continue // role not seeded in this deployment
		}
		if _, ok := idSet[role.ID]; ok {
			return true
		}
	}
	return false
}

// dedupeUints returns ids with duplicates removed, preserving first-seen order.
func dedupeUints(ids []uint) []uint {
	if len(ids) <= 1 {
		return ids
	}
	seen := make(map[uint]struct{}, len(ids))
	out := ids[:0:0]
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

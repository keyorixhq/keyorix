package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// RoleWithPermissions embeds a Role and includes its assigned permissions.
type RoleWithPermissions struct {
	models.Role
	Permissions []*models.Permission `json:"permissions"`
}

// UserRoleAssignment holds a user's identity alongside their assigned roles.
type UserRoleAssignment struct {
	UserID   uint           `json:"user_id"`
	Username string         `json:"username"`
	Email    string         `json:"email"`
	Roles    []*models.Role `json:"roles"`
}

// ListPermissions returns all permissions.
func (c *KeyorixCore) ListPermissions(ctx context.Context) ([]*models.Permission, error) {
	permissions, err := c.storage.ListPermissions(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return permissions, nil
}

// GetRoleWithPermissions returns a role and its assigned permissions.
func (c *KeyorixCore) GetRoleWithPermissions(ctx context.Context, roleID uint) (*models.Role, []*models.Permission, error) {
	role, err := c.storage.GetRole(ctx, roleID)
	if err != nil {
		return nil, nil, err
	}
	perms, err := c.storage.GetRolePermissions(ctx, roleID)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return role, perms, nil
}

// AssignPermissionToRole verifies both exist, requires the actor already hold the
// permission being bundled, assigns it, and records an RBAC audit event. actorID is
// the acting principal (0 = none).
//
// #169: CreateRole/UpdateRole are gated only by the narrower "roles.write" — without
// this check, a roles.write holder could bundle an arbitrary admin-tier permission
// (system.write, roles.assign, users.impersonate, ...) into a role's DEFINITION with
// zero check that they hold it themselves, then have that role granted to them
// through any ordinary (non-admin) grant path — bypassing every admin-rank-ceiling
// check on the GRANT step (#93/#107/#141/#147/#161/#165 and friends), since none of
// those fixes touch role-definition time. Roles are global catalog objects (not
// project/environment-scoped), so the actor must hold the permission at GLOBAL scope
// — matching how roles.write itself is gated (RequirePermission always resolves to
// ScopeGlobal). c.Authorize already includes the admin-role bypass, so a genuine
// global admin is unaffected.
func (c *KeyorixCore) AssignPermissionToRole(ctx context.Context, actorID, roleID, permissionID uint) error {
	if _, err := c.storage.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotFound", nil), err)
	}
	perm, err := c.storage.GetPermission(ctx, permissionID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	// actorID 0 is the established "system" pseudo-actor used by startup/background
	// processes that are never attacker-reachable (e.g. ReconcileRBACPermissions's
	// additive, non-clobbering, once-per-boot top-up of newly-added canonical
	// permissions — #293). Those callers have no role of their own to hold the
	// permission being bundled, so the #169 self-permission check only applies to a
	// real (non-zero) actor.
	if actorID != 0 {
		if ok, aerr := c.Authorize(ctx, actorID, perm.Name, Scope{}); aerr != nil {
			return fmt.Errorf("failed to resolve actor authority: %w", aerr)
		} else if !ok {
			return fmt.Errorf("cannot assign permission %q to a role: you do not hold it yourself", perm.Name)
		}
	}
	if err := c.storage.AssignPermissionToRole(ctx, roleID, permissionID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.LogPermissionAssigned(ctx, actorID, roleID, permissionID)
	return nil
}

// RemovePermissionFromRole verifies the role exists, removes the permission, and
// records an RBAC audit event. actorID is the acting principal (0 = none).
func (c *KeyorixCore) RemovePermissionFromRole(ctx context.Context, actorID, roleID, permissionID uint) error {
	if _, err := c.storage.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotFound", nil), err)
	}
	if err := c.storage.RemovePermissionFromRole(ctx, roleID, permissionID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.LogPermissionRemoved(ctx, actorID, roleID, permissionID)
	return nil
}

// GetGroupRoles returns all roles assigned to a group.
func (c *KeyorixCore) GetGroupRoles(ctx context.Context, groupID uint) ([]*models.Role, error) {
	roles, err := c.storage.GetGroupRoles(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return roles, nil
}

// GetGroupRoleGrants returns a group's roles each with its time-bound expiry
// (nil = permanent), so the API can surface remaining time on a just-in-time grant.
func (c *KeyorixCore) GetGroupRoleGrants(ctx context.Context, groupID uint) ([]*storage.GroupRoleGrant, error) {
	grants, err := c.storage.GetGroupRoleGrants(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return grants, nil
}

// AssignRoleToGroup verifies both exist then assigns the role at scope and
// records an RBAC audit event. actorID is the acting principal (0 = none).
func (c *KeyorixCore) AssignRoleToGroup(ctx context.Context, actorID, groupID, roleID uint, scope Scope) error {
	if _, err := c.storage.GetGroup(ctx, groupID); err != nil {
		return fmt.Errorf("group not found: %w", err)
	}
	if _, err := c.storage.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotFound", nil), err)
	}
	if err := c.storage.AssignRoleToGroup(ctx, groupID, roleID, scope); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.LogGroupRoleAssigned(ctx, actorID, groupID, roleID, scope)
	return nil
}

// RemoveRoleFromGroup verifies the group exists then removes the role at scope
// and records an RBAC audit event. actorID is the acting principal (0 = none).
func (c *KeyorixCore) RemoveRoleFromGroup(ctx context.Context, actorID, groupID, roleID uint, scope Scope) error {
	if _, err := c.storage.GetGroup(ctx, groupID); err != nil {
		return fmt.Errorf("group not found: %w", err)
	}
	if err := c.storage.RemoveRoleFromGroup(ctx, groupID, roleID, scope); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.LogGroupRoleRemoved(ctx, actorID, groupID, roleID, scope)
	return nil
}

// ListRolesWithPermissions returns all roles with their permission sets.
func (c *KeyorixCore) ListRolesWithPermissions(ctx context.Context) ([]*RoleWithPermissions, error) {
	roles, err := c.storage.ListRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	result := make([]*RoleWithPermissions, 0, len(roles))
	for _, role := range roles {
		perms, err := c.storage.GetRolePermissions(ctx, role.ID)
		if err != nil {
			perms = []*models.Permission{}
		}
		result = append(result, &RoleWithPermissions{
			Role:        *role,
			Permissions: perms,
		})
	}
	return result, nil
}

// GetUserRoleAssignment returns a user's identity and assigned roles.
func (c *KeyorixCore) GetUserRoleAssignment(ctx context.Context, userID uint) (*UserRoleAssignment, error) {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	roles, err := c.storage.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &UserRoleAssignment{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		Roles:    roles,
	}, nil
}

// GetUserRolesByID returns the roles assigned to the given user ID.
func (c *KeyorixCore) GetUserRolesByID(ctx context.Context, userID uint) ([]*models.Role, error) {
	roles, err := c.storage.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return roles, nil
}

// GetUserPermissionsByID returns a user's effective permission set — the
// de-duplicated union of permissions across every role assigned to the user. This
// is the "what can this user do" view for dashboards and access reviews; the CLI's
// list-permissions assembles the same set client-side. Empty for an unknown user.
func (c *KeyorixCore) GetUserPermissionsByID(ctx context.Context, userID uint) ([]*storage.Permission, error) {
	perms, err := c.storage.GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return perms, nil
}

// SetUserRoles does a full replacement of the roles assigned to a user at the
// given scope. Only assignments at exactly that scope are considered: roles
// present there but not in roleIDs are removed; roles in roleIDs not already
// assigned there are added. Assignments at other scopes are left untouched.
func (c *KeyorixCore) SetUserRoles(ctx context.Context, actorID, userID uint, roleIDs []uint, scope Scope) error {
	current, err := c.storage.GetUserRoleIDsExact(ctx, userID, scope)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	currentSet := make(map[uint]bool, len(current))
	for _, id := range current {
		currentSet[id] = true
	}
	newSet := make(map[uint]bool, len(roleIDs))
	for _, id := range roleIDs {
		newSet[id] = true
	}
	for _, id := range current {
		if !newSet[id] {
			if err := c.RemoveUserRole(ctx, actorID, userID, id, scope); err != nil {
				return err
			}
		}
	}
	for _, id := range roleIDs {
		if !currentSet[id] {
			if err := c.AssignUserRole(ctx, actorID, userID, id, scope); err != nil {
				return err
			}
		}
	}
	return nil
}

// AssignUserRole assigns a role to a user at the given scope and records an RBAC
// audit event. actorID is the acting principal (0 when unauthenticated, e.g. a
// local CLI invocation). This is the audited choke point all role-assignment
// paths funnel through.
func (c *KeyorixCore) AssignUserRole(ctx context.Context, actorID, userID, roleID uint, scope Scope) error {
	if err := c.storage.AssignRole(ctx, userID, roleID, scope); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.LogRoleAssigned(ctx, actorID, userID, roleID, scope)
	return nil
}

// RemoveUserRole removes a role from a user at the given scope and records an
// RBAC audit event. See AssignUserRole for actorID semantics. It refuses to remove
// the last install administrator (see guardLastGlobalAdmin). This is the choke point
// SetUserRoles and the HTTP/gRPC role-removal handlers funnel through.
func (c *KeyorixCore) RemoveUserRole(ctx context.Context, actorID, userID, roleID uint, scope Scope) error {
	if err := c.guardLastGlobalAdmin(ctx, userID, roleID, scope); err != nil {
		return err
	}
	if err := c.storage.RemoveRole(ctx, userID, roleID, scope); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	c.LogRoleRemoved(ctx, actorID, userID, roleID, scope)
	return nil
}

// installAdminRoleNames are the roles that confer install-wide administration when
// held at the global scope (project 0). Removing the last such assignment leaves the
// install with no one able to manage users, roles, or settings.
var installAdminRoleNames = []string{"super_admin", "admin", "system_admin"}

// installAdminRoleIDSet resolves installAdminRoleNames to their role IDs (skipping
// any that a given install did not seed).
func (c *KeyorixCore) installAdminRoleIDSet(ctx context.Context) map[uint]bool {
	set := make(map[uint]bool, len(installAdminRoleNames))
	for _, name := range installAdminRoleNames {
		if role, err := c.storage.GetRoleByName(ctx, name); err == nil && role != nil {
			set[role.ID] = true
		}
	}
	return set
}

// guardLastGlobalAdmin refuses to remove a user's global (install-wide) admin role
// when no other global admin-role assignment would remain — preventing a
// self-inflicted or malicious-insider lockout that strands the install with no
// administrator (and no recovery short of DB surgery). Only the global scope is
// guarded: a project-scoped admin can always be restored by a global admin.
func (c *KeyorixCore) guardLastGlobalAdmin(ctx context.Context, userID, roleID uint, scope Scope) error {
	if scope.ProjectID != 0 || scope.EnvironmentID != 0 {
		return nil // not the global scope — project admins are recoverable
	}
	adminIDs := c.installAdminRoleIDSet(ctx)
	if !adminIDs[roleID] {
		return nil // not removing an install-admin role
	}
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, 0)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, a := range assignments {
		if !adminIDs[a.RoleID] {
			continue
		}
		// Ignore the exact assignment being removed; any OTHER global admin grant
		// (held by another user, or by a group) means governance survives.
		if a.PrincipalType == "user" && a.PrincipalID == userID && a.RoleID == roleID {
			continue
		}
		return nil
	}
	return fmt.Errorf("refusing to remove the last install administrator: the install would be left with no super_admin/admin/system_admin at the global scope and no one able to manage users, roles, or settings")
}

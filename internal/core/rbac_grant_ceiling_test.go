package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #93/#107/#141: a roles.assign holder with no other authority must not be able to
// GRANT a role bundling a permission they don't hold themselves — the "grant"
// counterpart to #169's "definition" fix (TestAssignPermissionToRole_*, above).
// "editor" here stands in for any pre-existing/seeded permission-rich role: the
// attacker never touched its definition, only its grant.
func TestAssignUserRole_RequiresActorHoldRolePermissions(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "editor"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.delete", Resource: "secrets", Action: "delete"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)

	const attacker = uint(9) // holds roles.assign in the real exploit (irrelevant here — no roles at all)
	const target = uint(10)
	err := c.AssignUserRole(ctx, attacker, target, 2, Scope{ProjectID: 3})
	require.Error(t, err, "a roles.assign holder must not grant a role bundling a permission they don't hold themselves")
	assert.Contains(t, err.Error(), "do not hold permission")

	var count int64
	require.NoError(t, db.Model(&models.UserRole{}).Count(&count).Error)
	assert.Zero(t, count, "the grant must not have been persisted")
}

// The same escalation-by-proxy shape works against a THIRD party too, not just a
// self-grant — a roles.assign holder must not be able to hand a permission-rich
// role to anyone else either.
func TestAssignUserRole_CannotGrantToThirdPartyEither(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "editor"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.delete", Resource: "secrets", Action: "delete"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)
	// attacker DOES hold roles.assign at the project (the gate every grant path
	// already enforces at the router/handler layer) — but not secrets.delete.
	require.NoError(t, db.Create(&models.Permission{ID: 2, Name: "roles.assign", Resource: "roles", Action: "assign"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 3, Name: "role-manager"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 3, PermissionID: 2}).Error)

	const attacker = uint(9)
	const victim = uint(20) // a third party, not the attacker themselves
	require.NoError(t, db.Create(&models.UserRole{UserID: attacker, RoleID: 3, ProjectID: 3}).Error)

	err := c.AssignUserRole(ctx, attacker, victim, 2, Scope{ProjectID: 3})
	require.Error(t, err, "holding roles.assign alone must not be enough to grant a role bundling secrets.delete")
	assert.Contains(t, err.Error(), "do not hold permission")
}

// A project-scoped holder of the bundled permission cannot use it to grant the
// role at a BROADER (global) scope than they hold it at — the ceiling check
// resolves the actor's authority AT THE TARGET SCOPE, not anywhere.
func TestAssignUserRole_ScopedHolderCannotGrantAtBroaderScope(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "editor"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.delete", Resource: "secrets", Action: "delete"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 3, Name: "holder"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 3, PermissionID: 1}).Error)

	const attacker = uint(9)
	const target = uint(10)
	// attacker holds secrets.delete only at project 3, not globally.
	require.NoError(t, db.Create(&models.UserRole{UserID: attacker, RoleID: 3, ProjectID: 3}).Error)

	err := c.AssignUserRole(ctx, attacker, target, 2, Scope{}) // global grant attempt
	require.Error(t, err, "a project-scoped holder must not grant the role globally")
	assert.Contains(t, err.Error(), "do not hold permission")

	// The SAME grant at the project scope they actually hold the permission at succeeds.
	require.NoError(t, c.AssignUserRole(ctx, attacker, target, 2, Scope{ProjectID: 3}))
}

// An actor who genuinely holds every bundled permission (directly, at an
// equal-or-broader scope) may grant the role — the fix must not block the
// legitimate case.
func TestAssignUserRole_HolderMayGrantRoleTheyQualifyFor(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "editor"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 2, Name: "secrets.write", Resource: "secrets", Action: "write"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 2}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 3, Name: "holder"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 3, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 3, PermissionID: 2}).Error)

	const holder = uint(9)
	const target = uint(10)
	require.NoError(t, db.Create(&models.UserRole{UserID: holder, RoleID: 3}).Error) // global grant

	require.NoError(t, c.AssignUserRole(ctx, holder, target, 2, Scope{ProjectID: 3}))

	var count int64
	require.NoError(t, db.Model(&models.UserRole{}).Where("user_id = ? AND role_id = ?", target, 2).Count(&count).Error)
	assert.Equal(t, int64(1), count)
}

// A global admin bypasses the grant-ceiling check (matching every other authz gate
// in this codebase, and #169's analogous bypass) — an admin can grant any role,
// including one bundling a permission they don't explicitly hold by name (the
// admin bypass in Authorize covers it).
func TestAssignUserRole_AdminBypassesCeiling(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "editor"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.delete", Resource: "secrets", Action: "delete"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)

	const admin = uint(9)
	const target = uint(10)
	require.NoError(t, db.Create(&models.UserRole{UserID: admin, RoleID: 1}).Error)

	require.NoError(t, c.AssignUserRole(ctx, admin, target, 2, Scope{ProjectID: 3}))
}

// actorID 0 is the established "system" pseudo-actor for genuinely non-attacker-
// reachable callers (the local CLI's AssignRoleToUser) — it must still bypass the
// grant-ceiling check exactly like it bypasses #169's AssignPermissionToRole check,
// so local/system-driven role assignment at bootstrap keeps working.
func TestAssignUserRole_SystemActorBypassesCeiling(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "editor"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.delete", Resource: "secrets", Action: "delete"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)

	const target = uint(10)
	require.NoError(t, c.AssignUserRole(ctx, 0, target, 2, Scope{ProjectID: 3}))

	var count int64
	require.NoError(t, db.Model(&models.UserRole{}).Where("user_id = ? AND role_id = ?", target, 2).Count(&count).Error)
	assert.Equal(t, int64(1), count)
}

// A role with NO bundled permissions at all (an empty/placeholder role) is always
// grantable — there is nothing to ceiling-check.
func TestAssignUserRole_EmptyRoleAlwaysGrantable(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "empty-role"}).Error)

	const actor = uint(9) // holds nothing
	const target = uint(10)
	require.NoError(t, c.AssignUserRole(ctx, actor, target, 2, Scope{ProjectID: 3}))
}

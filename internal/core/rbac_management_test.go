package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newRBACManagementCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.AuditEvent{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
	))
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

// #169: an actor with NO permissions at all — the CVE's own escalation shape (a
// roles.write holder with nothing else) — must not be able to bundle ANY permission
// into a role's definition, including a low-privilege one they don't personally hold.
func TestAssignPermissionToRole_RequiresActorHoldPermission(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "custom"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "system.write", Resource: "system", Action: "write"}).Error)

	const attacker = uint(9) // holds ONLY roles.write in the real exploit scenario, no roles at all here
	err := c.AssignPermissionToRole(ctx, attacker, 1, 1)
	require.Error(t, err, "an actor who doesn't hold system.write must not be able to bundle it into a role")
	assert.Contains(t, err.Error(), "do not hold it yourself")

	var count int64
	require.NoError(t, db.Model(&models.RolePermission{}).Count(&count).Error)
	assert.Zero(t, count, "the permission must not have been assigned")
}

// The escalation path the finding describes: attacker holds roles.write (only)
// PLUS the target permission at project scope, but not globally — bundling into a
// role (a global catalog object) must still require GLOBAL authority, not just
// scoped authority, since the resulting role could be granted anywhere.
func TestAssignPermissionToRole_ScopedHolderCannotBundleGlobally(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "custom"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "scoped-holder"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "system.write", Resource: "system", Action: "write"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)

	const attacker = uint(9)
	// attacker holds "system.write" only at project 3, not globally.
	require.NoError(t, db.Create(&models.UserRole{UserID: attacker, RoleID: 2, ProjectID: 3}).Error)

	err := c.AssignPermissionToRole(ctx, attacker, 1, 1)
	require.Error(t, err, "a project-scoped holder of system.write must not bundle it into a role, which is a global object")
}

// An actor who genuinely holds the permission (directly, at global scope) may bundle
// it into a role — the fix must not block the legitimate case.
func TestAssignPermissionToRole_HolderMaySelfBundle(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "custom"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "holder"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 2, PermissionID: 1}).Error)

	const holder = uint(9)
	require.NoError(t, db.Create(&models.UserRole{UserID: holder, RoleID: 2}).Error) // global grant

	require.NoError(t, c.AssignPermissionToRole(ctx, holder, 1, 1))

	var count int64
	require.NoError(t, db.Model(&models.RolePermission{}).Where("role_id = ? AND permission_id = ?", 1, 1).Count(&count).Error)
	assert.Equal(t, int64(1), count)
}

// A global admin bypasses the self-permission check (matching every other authz gate
// in this codebase) — an admin can bundle any permission into any role.
func TestAssignPermissionToRole_AdminBypasses(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "custom"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "admin"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "system.write", Resource: "system", Action: "write"}).Error)

	const admin = uint(9)
	require.NoError(t, db.Create(&models.UserRole{UserID: admin, RoleID: 2}).Error)

	require.NoError(t, c.AssignPermissionToRole(ctx, admin, 1, 1))
}

// RemovePermissionFromRole is purely subtractive (weakens a role) — it must NOT
// require the actor hold the permission being removed, unlike assignment.
func TestRemovePermissionFromRole_NoSelfPermissionRequired(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "custom"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "system.write", Resource: "system", Action: "write"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)

	const actor = uint(9) // holds nothing
	require.NoError(t, c.RemovePermissionFromRole(ctx, actor, 1, 1))
}

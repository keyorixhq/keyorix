package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #107 (group-path variant): RemoveRoleFromGroup, DeleteGroup, and
// RemoveUserFromGroup must each refuse an operation that would strand the install
// with zero global (project 0) admin-tier holders — mirroring the direct
// user-role-removal guard (guardLastGlobalAdmin), which they previously had zero
// call to.

// RemoveRoleFromGroup: removing the group's global admin role must be refused when
// no other admin route (user or group) survives.
func TestRemoveRoleFromGroup_RefusesLastGlobalAdmin(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 1, Name: "ops"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 1, RoleID: 1}).Error) // global admin grant

	err := c.RemoveRoleFromGroup(ctx, 0, 1, 1, Scope{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no super_admin/admin/system_admin at the global scope")

	// The grant is untouched.
	var count int64
	require.NoError(t, db.Model(&models.GroupRole{}).Count(&count).Error)
	assert.Equal(t, int64(1), count)
}

// RemoveRoleFromGroup: succeeds once another admin route (a direct user grant)
// exists — the guard must not over-block.
func TestRemoveRoleFromGroup_AllowsWhenAnotherAdminExists(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 1, Name: "ops"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 1, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.User{ID: 42, Username: "other-admin", IsActive: true}).Error) // #G03: must exist and be active to count as a surviving admin
	require.NoError(t, db.Create(&models.UserRole{UserID: 42, RoleID: 1}).Error) // another global admin

	require.NoError(t, c.RemoveRoleFromGroup(ctx, 0, 1, 1, Scope{}))
}

// RemoveRoleFromGroup: a non-admin role grant is never blocked, regardless of the
// install's admin count.
func TestRemoveRoleFromGroup_NonAdminRoleAlwaysRemovable(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 3, Name: "editor"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 1, Name: "ops"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 1, RoleID: 3}).Error)

	require.NoError(t, c.RemoveRoleFromGroup(ctx, 0, 1, 3, Scope{}))
}

// DeleteGroup: deleting a group holding the install's last global admin grant
// must be refused — deleting the group cascades to remove EVERY role it holds.
func TestDeleteGroup_RefusesWhenHoldsLastGlobalAdminRole(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 1, Name: "ops"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 1, RoleID: 1}).Error)

	err := c.DeleteGroup(ctx, 0, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "last administrative role grant")

	// The group must still exist.
	g, gerr := c.GetGroup(ctx, 1)
	require.NoError(t, gerr)
	assert.Equal(t, uint(1), g.ID)
}

// DeleteGroup: succeeds once another admin route survives.
func TestDeleteGroup_AllowsWhenAnotherAdminExists(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 1, Name: "ops"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 1, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.User{ID: 42, Username: "other-admin", IsActive: true}).Error) // #G03: must exist and be active to count as a surviving admin
	require.NoError(t, db.Create(&models.UserRole{UserID: 42, RoleID: 1}).Error)

	require.NoError(t, c.DeleteGroup(ctx, 0, 1))
}

// DeleteGroup: a group with no admin-tier grant is always deletable, regardless of
// the install's overall admin count (must not over-block unrelated groups).
func TestDeleteGroup_NonAdminGroupAlwaysDeletable(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{ID: 3, Name: "editor"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 1, Name: "ops-team"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 1, RoleID: 3}).Error)

	require.NoError(t, c.DeleteGroup(ctx, 0, 1))
}

// RemoveUserFromGroup: the group's role grant row SURVIVES membership removal —
// this is the case a simple "does another assignment row exist" check cannot
// catch. Removing the sole member of an admin-conferring group must be refused
// when no other admin route exists.
func TestRemoveUserFromGroup_RefusesLastAdminMember(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.AutoMigrate(&models.User{}))
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 1, Name: "ops"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 1, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.User{ID: 42, Username: "sole-admin", Email: "sole@example.com"}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 42, GroupID: 1}).Error)

	err := c.RemoveUserFromGroup(ctx, 0, 42, 1, 0) // projectID=0: global membership
	require.Error(t, err)
	assert.Contains(t, err.Error(), "last administrator")

	// The membership is untouched.
	var count int64
	require.NoError(t, db.Model(&models.UserGroup{}).Count(&count).Error)
	assert.Equal(t, int64(1), count)
}

// RemoveUserFromGroup: succeeds once another member of the SAME group would still
// carry the admin authority forward.
func TestRemoveUserFromGroup_AllowsWhenAnotherGroupMemberRemains(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.AutoMigrate(&models.User{}))
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 1, Name: "ops"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 1, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.User{ID: 42, Username: "admin1", Email: "a1@example.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 43, Username: "admin2", Email: "a2@example.com"}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 42, GroupID: 1}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 43, GroupID: 1}).Error)

	require.NoError(t, c.RemoveUserFromGroup(ctx, 0, 42, 1, 0)) // projectID=0: global membership
}

// RemoveUserFromGroup: succeeds once another admin route survives (a direct grant
// on a different user), even with only one member in the admin-conferring group.
func TestRemoveUserFromGroup_AllowsWhenDirectAdminExists(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.AutoMigrate(&models.User{}))
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "admin"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 1, Name: "ops"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 1, RoleID: 1}).Error)
	require.NoError(t, db.Create(&models.User{ID: 42, Username: "sole-member", Email: "sm@example.com"}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 42, GroupID: 1}).Error)
	require.NoError(t, db.Create(&models.User{ID: 99, Username: "other-admin", IsActive: true}).Error) // #G03: must exist and be active to count as a surviving admin
	require.NoError(t, db.Create(&models.UserRole{UserID: 99, RoleID: 1}).Error) // direct global admin

	require.NoError(t, c.RemoveUserFromGroup(ctx, 0, 42, 1, 0)) // projectID=0: global membership
}

// RemoveUserFromGroup: membership in a group with no admin-tier grant is always
// removable, regardless of the install's overall admin count.
func TestRemoveUserFromGroup_NonAdminGroupAlwaysRemovable(t *testing.T) {
	c, db := newRBACManagementCore(t)
	ctx := context.Background()
	require.NoError(t, db.AutoMigrate(&models.User{}))
	require.NoError(t, db.Create(&models.Role{ID: 3, Name: "editor"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 1, Name: "ops-team"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 1, RoleID: 3}).Error)
	require.NoError(t, db.Create(&models.User{ID: 42, Username: "alice", Email: "alice@example.com"}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 42, GroupID: 1}).Error)

	require.NoError(t, c.RemoveUserFromGroup(ctx, 0, 42, 1, 0)) // projectID=0: global membership
}

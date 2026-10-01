// local_rbac_deleterole_cascade_test.go — SESSION-AT AT1 row 2: DeleteRole
// hard-deletes the roles row but, before this fix, left every UserRole/
// GroupRole/MachineIdentityRole/RolePermission/ConnectRefGrant row
// referencing that role's ID in place -- none of these RoleID columns are
// GORM associations, so AutoMigrate creates no FK constraint on either
// backend, and nothing else removes them. Confirmed separately (see this
// session's report) that the orphan is inert, not a privilege-inheritance
// hole -- GORM's AUTOINCREMENT never reissues a deleted role's ID, and every
// authorization query joins against the live roles table, so an orphaned
// grant row matches nothing live. This is a data-hygiene fix, not a
// security closure.
//
// package store_test (not store): needs kxstorage.MigrateExisting for the
// FULL production schema (not a hand-picked AutoMigrate subset -- a narrow
// list would silently hide exactly this kind of cross-model cascade gap by
// never creating the sibling tables in the first place), which would be an
// import cycle from inside package store itself (internal/storage imports
// internal/storage/store from factory.go).
package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/identity"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newFullSchemaStore opens a shared-cache in-memory SQLite DB migrated with
// the FULL production schema and returns both the LocalStorage (for the
// method under test) and the raw *gorm.DB (for seeding fixture rows and
// verifying post-delete state directly, since LocalStorage's own db field
// isn't reachable from this external test package).
func newFullSchemaStore(t *testing.T) (*store.LocalStorage, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, kxstorage.MigrateExisting(db))
	return store.NewLocalStorage(db), db
}

// TestDeleteRole_CascadesEveryRoleIDReference seeds one row in each of the
// five tables that reference a role by RoleID, deletes the role, and asserts
// all five are gone -- not just that the role itself is gone.
func TestDeleteRole_CascadesEveryRoleIDReference(t *testing.T) {
	ctx := context.Background()
	ls, db := newFullSchemaStore(t)

	roleName, err := identity.NewFoldedName("cascade-target")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, roleName, "role being deleted")
	require.NoError(t, err)

	user := &models.User{Username: "u1", Email: "u1@example.com"}
	require.NoError(t, db.WithContext(ctx).Create(user).Error)
	group := &models.Group{Name: "g1"}
	require.NoError(t, db.WithContext(ctx).Create(group).Error)
	machine := &models.MachineIdentity{Name: "m1"}
	require.NoError(t, db.WithContext(ctx).Create(machine).Error)
	perm := &models.Permission{Name: "cascade.perm", Resource: "x", Action: "y"}
	require.NoError(t, db.WithContext(ctx).Create(perm).Error)

	require.NoError(t, db.WithContext(ctx).Create(&models.UserRole{
		UserID: user.ID, RoleID: role.ID,
	}).Error)
	require.NoError(t, db.WithContext(ctx).Create(&models.GroupRole{
		GroupID: group.ID, RoleID: role.ID,
	}).Error)
	require.NoError(t, db.WithContext(ctx).Create(&models.MachineIdentityRole{
		MachineIdentityID: machine.ID, RoleID: role.ID,
	}).Error)
	require.NoError(t, db.WithContext(ctx).Create(&models.RolePermission{
		RoleID: role.ID, PermissionID: perm.ID,
	}).Error)
	require.NoError(t, db.WithContext(ctx).Create(&models.ConnectRefGrant{
		RoleID: role.ID, Connector: "vault", RefPrefix: "secret/",
	}).Error)

	counts, err := ls.DeleteRole(ctx, role.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, counts.UserAssignments, "DeleteRole's returned counts must reflect the one UserRole row actually removed")
	assert.Equal(t, 1, counts.GroupAssignments, "DeleteRole's returned counts must reflect the one GroupRole row actually removed")
	assert.Equal(t, 1, counts.MachineAssignments, "DeleteRole's returned counts must reflect the one MachineIdentityRole row actually removed")

	_, err = ls.GetRole(ctx, role.ID)
	assert.Error(t, err, "role itself must be gone")

	var count int64
	require.NoError(t, db.WithContext(ctx).Model(&models.UserRole{}).Where("role_id = ?", role.ID).Count(&count).Error)
	assert.Zero(t, count, "UserRole row referencing the deleted role must be gone")

	require.NoError(t, db.WithContext(ctx).Model(&models.GroupRole{}).Where("role_id = ?", role.ID).Count(&count).Error)
	assert.Zero(t, count, "GroupRole row referencing the deleted role must be gone")

	require.NoError(t, db.WithContext(ctx).Model(&models.MachineIdentityRole{}).Where("role_id = ?", role.ID).Count(&count).Error)
	assert.Zero(t, count, "MachineIdentityRole row referencing the deleted role must be gone")

	require.NoError(t, db.WithContext(ctx).Model(&models.RolePermission{}).Where("role_id = ?", role.ID).Count(&count).Error)
	assert.Zero(t, count, "RolePermission row referencing the deleted role must be gone")

	require.NoError(t, db.WithContext(ctx).Model(&models.ConnectRefGrant{}).Where("role_id = ?", role.ID).Count(&count).Error)
	assert.Zero(t, count, "ConnectRefGrant row referencing the deleted role must be gone")
}

// TestDeleteRole_NotFound_NoCascadeSideEffects documents that a nonexistent
// role ID fails before any cascade delete runs (RowsAffected==0 on the role
// delete itself, inside the same transaction), so there is nothing for the
// unconditional sibling-table deletes to clean up or corrupt.
func TestDeleteRole_NotFound_NoCascadeSideEffects(t *testing.T) {
	ctx := context.Background()
	ls, _ := newFullSchemaStore(t)

	_, err := ls.DeleteRole(ctx, 999999)
	assert.Error(t, err)
}

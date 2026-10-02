// local_rbac_deleterole_cascade_postgres_test.go — Postgres variant of
// TestDeleteRole_CascadesEveryRoleIDReference (local_rbac_deleterole_cascade_test.go),
// per PR #2357 review: the SQLite variant proves the cascade's five DELETE
// statements remove the right rows under SQLite's dialect; this proves the
// identical SQL (tx.Where("role_id = ?", id).Delete(...)) behaves the same
// way against Postgres, where GORM's query-building and the driver's type
// handling differ from SQLite's.
//
// package store (not store_test): reuses this package's own
// pgTestDSN/pgIsolatedSchemaDSN/pgOpen helpers (postgres_contention_helpers_test.go,
// the established mechanism every other _Postgres variant in this repo
// already uses — see internal/core/create_ops_pg_savepoint_test.go for the
// same idiom). Can't use kxstorage.MigrateExisting here the way the SQLite
// variant does (package store_test, to dodge an internal/storage ->
// internal/storage/store import cycle) since those two package identities
// are mutually exclusive for one file — AutoMigrate with the exact set of
// models this test needs is deliberate and complete here, not a narrow,
// accidentally-incomplete list: every table DeleteRole's cascade touches,
// plus the parent rows (User/Group/MachineIdentity/Permission) their FK-ish
// columns reference.
package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestDeleteRole_CascadesEveryRoleIDReference_Postgres(t *testing.T) {
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)
	db := pgOpen(t, dsn)
	require.NoError(t, db.AutoMigrate(
		&models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.User{}, &models.UserRole{}, &models.Group{}, &models.GroupRole{},
		&models.MachineIdentity{}, &models.MachineIdentityRole{}, &models.ConnectRefGrant{},
	))
	ls := NewLocalStorage(db)
	ctx := context.Background()

	roleName, err := identity.NewFoldedName("cascade-target-pg")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, roleName, "role being deleted")
	require.NoError(t, err)

	user := &models.User{Username: "u1", Email: "u1@example.com"}
	require.NoError(t, db.WithContext(ctx).Create(user).Error)
	group := &models.Group{Name: "g1"}
	require.NoError(t, db.WithContext(ctx).Create(group).Error)
	machine := &models.MachineIdentity{Name: "m1"}
	require.NoError(t, db.WithContext(ctx).Create(machine).Error)
	perm := &models.Permission{Name: "cascade.perm.pg", Resource: "x", Action: "y"}
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
	assert.Equal(t, 1, counts.UserAssignments)
	assert.Equal(t, 1, counts.GroupAssignments)
	assert.Equal(t, 1, counts.MachineAssignments)

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

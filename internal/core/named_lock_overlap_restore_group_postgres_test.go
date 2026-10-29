// named_lock_overlap_restore_group_postgres_test.go — NAMEDLOCK-OVERLAP-2, the
// PostgreSQL half of named_lock_overlap_restore_group_test.go: replica B's
// admin-role grant to the soft-deleted group starts inside replica A's restore
// transaction (after A's fence took the group key with LockNamedKeyInTx and
// re-checked the ceiling, before A's restore write). B's grant transaction must
// wait on that key until A has committed: a non-administrator's restore can
// then never commit a group carrying an admin role it did not check.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestNamedLockOverlap_RestoreGroup_ConcurrentWriteTransactions_Postgres(t *testing.T) {
	t.Parallel()
	dsn, setupDB := newPGLastAdminSchemaDSN(t)
	require.NoError(t, setupDB.AutoMigrate(&models.SoDPolicy{}))
	var assign models.Permission
	require.NoError(t, setupDB.Where("name = ?", "roles.assign").First(&assign).Error)
	admin := models.Role{Name: "admin", BypassesPermissionChecks: true, AssignableScope: models.RoleAssignableAny}
	assigner := models.Role{Name: "assigner", AssignableScope: models.RoleAssignableAny}
	require.NoError(t, setupDB.Create(&admin).Error)
	require.NoError(t, setupDB.Create(&assigner).Error)
	require.NoError(t, setupDB.Create(&models.RolePermission{RoleID: assigner.ID, PermissionID: assign.ID}).Error)
	restorer := models.User{Username: "rg-assigner", UsernameFolded: "rg-assigner", IsActive: true, AccountState: AccountActive}
	granter := models.User{Username: "rg-admin", UsernameFolded: "rg-admin", IsActive: true, AccountState: AccountActive}
	require.NoError(t, setupDB.Create(&restorer).Error)
	require.NoError(t, setupDB.Create(&granter).Error)
	require.NoError(t, setupDB.Create(&models.UserRole{UserID: restorer.ID, RoleID: assigner.ID}).Error)
	require.NoError(t, setupDB.Create(&models.UserRole{UserID: granter.ID, RoleID: admin.ID}).Error)
	group := models.Group{Name: "rg-dormant"}
	require.NoError(t, setupDB.Create(&group).Error)
	require.NoError(t, setupDB.Delete(&group).Error)
	closePG(setupDB)

	errA, errB, early := overlapPGRun(t, dsn, func(start func()) *storagetest.StoreHooks {
		return &storagetest.StoreHooks{RestoreGroup: func(next storage.Storage, ctx context.Context, id uint) error {
			start() // inside A's restore transaction, after its fence and ceiling re-check
			return next.RestoreGroup(ctx, id)
		}}
	}, func(ctx context.Context, c *KeyorixCore) error {
		_, err := c.RestoreGroup(ctx, restorer.ID, group.ID)
		return err
	}, func(ctx context.Context, c *KeyorixCore) error {
		return c.AssignGroupRoleWithExpiry(ctx, granter.ID, group.ID, admin.ID, Scope{}, time.Now().Add(time.Hour), false)
	})

	require.NoError(t, errA, "replica A's restore checked a group with no role and holds the group key: it commits")
	require.False(t, early, "replica B's grant transaction must wait for A's restore (it finished while A's was open: %v)", errB)
	require.NoError(t, errB, "replica B, an administrator, grants after A's restore committed")
}

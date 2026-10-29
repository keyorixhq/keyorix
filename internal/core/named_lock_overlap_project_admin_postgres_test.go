// named_lock_overlap_project_admin_postgres_test.go — NAMEDLOCK-OVERLAP-2, the
// PostgreSQL half of named_lock_overlap_project_admin_test.go: replica B's
// removal of the other project admin starts inside replica A's removal
// transaction (at A's write, after A's fence took the project's key with
// LockNamedKeyInTx). B's transaction must wait on that key, then its re-check
// sees A's removal and refuses.
package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestNamedLockOverlap_ProjectAdmin_ConcurrentWriteTransactions_Postgres(t *testing.T) {
	t.Parallel()
	dsn, setupDB := newPGLastAdminSchemaDSN(t)
	proj := models.Project{Name: "proj-admin-overlap"}
	require.NoError(t, setupDB.Create(&proj).Error)
	var assign models.Permission
	require.NoError(t, setupDB.Where("name = ?", "roles.assign").First(&assign).Error)
	role := models.Role{Name: "proj_admin"}
	require.NoError(t, setupDB.Create(&role).Error)
	require.NoError(t, setupDB.Create(&models.RolePermission{RoleID: role.ID, PermissionID: assign.ID}).Error)
	var users [2]uint
	for i, name := range []string{"pa-1", "pa-2"} {
		u := models.User{Username: name, UsernameFolded: name, IsActive: true, AccountState: AccountActive}
		require.NoError(t, setupDB.Create(&u).Error)
		require.NoError(t, setupDB.Create(&models.UserRole{UserID: u.ID, RoleID: role.ID, ProjectID: proj.ID}).Error)
		users[i] = u.ID
	}
	closePG(setupDB)
	scope := Scope{ProjectID: proj.ID}

	errA, errB, early := overlapPGRun(t, dsn, func(start func()) *storagetest.StoreHooks {
		return &storagetest.StoreHooks{RemoveRole: func(next storage.Storage, ctx context.Context, userID, roleID uint, sc storage.Scope) error {
			start() // inside A's removal transaction, after its fence
			return next.RemoveRole(ctx, userID, roleID, sc)
		}}
	}, func(ctx context.Context, c *KeyorixCore) error {
		return c.RemoveUserRole(ctx, 0, users[0], role.ID, scope)
	}, func(ctx context.Context, c *KeyorixCore) error {
		return c.RemoveUserRole(ctx, 0, users[1], role.ID, scope)
	})

	check := pgOpen(t, dsn)
	defer closePG(check)
	var left int64
	require.NoError(t, check.Model(&models.UserRole{}).Where("role_id = ? AND project_id = ?", role.ID, proj.ID).Count(&left).Error)
	require.NoError(t, errA, "replica A held the project's transaction key first and must win")
	require.False(t, early, "replica B's removal transaction must wait for A's (it finished while A's was open: %v)", errB)
	require.Equal(t, int64(1), left, "both project admins were removed by two overlapping transactions (A: %v, B: %v)", errA, errB)
	require.ErrorContains(t, errB, "last administrator", "replica B is refused by the in-transaction re-check")
}

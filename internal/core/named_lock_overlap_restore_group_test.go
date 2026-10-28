// named_lock_overlap_restore_group_test.go — NAMEDLOCK-OVERLAP-2, family
// "RestoreGroup" (docs/design/named-lock-overlap.md; was NEEDS ANDREI, closed
// with LockNamedKeyInTx): RestoreGroup takes sodGrantLockKey("group", id) with
// LockNamedKeyInTx in its restore transaction and re-runs its ceiling check on
// the group's roles as tx reads them; every grant to a group takes the same
// key in its own transaction. Losing the named lock mid-section therefore
// cannot let a non-administrator restore a group that just gained an
// administrative role (#2455).
//
// Holder A (actor 98, roles.assign but no admin role) restores soft-deleted
// group 40, which holds no role; its lock is lost after its ceiling check
// passed, holder B (another replica, actor 99, an administrator) grants group
// 40 the admin role with an expiry (the storage write does not check the
// group's soft-delete state) and commits, then A restores. A must be refused.
package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func TestNamedLockOverlap_RestoreGroup_CeilingSeesConcurrentAdminGrant(t *testing.T) {
	t.Parallel()
	db := sqliteDB(t, "overlap_restore_group.db")
	require.NoError(t, db.AutoMigrate(&models.SoDPolicy{}))
	require.NoError(t, db.Create(&models.Role{ID: 9, Name: "admin", BypassesPermissionChecks: true, AssignableScope: models.RoleAssignableAny}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "assigner", AssignableScope: models.RoleAssignableAny}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 10, PermissionID: 1}).Error)
	for _, u := range []models.User{
		{ID: 98, Username: "assigner", IsActive: true, AccountState: core.AccountActive},
		{ID: 99, Username: "admin", IsActive: true, AccountState: core.AccountActive},
	} {
		require.NoError(t, db.Create(&u).Error)
	}
	require.NoError(t, db.Create(&models.UserRole{UserID: 98, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 99, RoleID: 9}).Error)
	group := models.Group{ID: 40, Name: "dormant"}
	require.NoError(t, db.Create(&group).Error)
	require.NoError(t, db.Delete(&group).Error) // soft delete

	replicaB := core.NewKeyorixCore(store.NewLocalStorage(db))
	overlap := newLockLossOverlap(t, "sod-grant:group:40", func(ctx context.Context) error {
		return replicaB.AssignGroupRoleWithExpiry(ctx, 99, 40, 9, core.Scope{}, time.Now().Add(time.Hour), false)
	})
	replicaA := core.NewKeyorixCore(overlap.store(store.NewLocalStorage(db)))

	_, errA := replicaA.RestoreGroup(context.Background(), 98, 40)
	t.Logf("holder A: %v; holder B: %v", errA, overlap.secondErr)
	overlap.requireFired()

	require.NoError(t, overlap.secondErr, "holder B, an administrator, may grant the admin role")
	var live int64
	require.NoError(t, db.Model(&models.Group{}).Where("id = 40").Count(&live).Error)
	require.Zero(t, live,
		"holder A, not an administrator, restored a group that gained an admin role inside A's lost-lock window (A's error: %v)", errA)
	require.ErrorContains(t, errA, "only an administrator can restore", "A is refused by the in-transaction ceiling check")
}

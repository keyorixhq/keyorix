package core

// rbac_reconcile_settle_before_grant_test.go — REVIEW-4560 M1: a (permission,
// role) pair leaves the pending row durably BEFORE its grant is attempted, and
// is owed again only if the grant fails. Before, the row was settled once,
// after every grant: a failed final save (a write error, or the lock-loss path
// cancelling ctx) left landed pairs listed, and the next startup re-granted a
// permission an operator had removed in between.

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
)

// failPendingSavesAfterGrant returns a core over c's store in which every write
// of the pending row fails once a grant has been attempted, and the first
// grant attempt fails if failFirstGrant is set. fired reports whether a save
// was refused.
func failPendingSavesAfterGrant(c *KeyorixCore, failFirstGrant bool) (faulty *KeyorixCore, fired *atomic.Bool) {
	var attempted atomic.Int32
	fired = &atomic.Bool{}
	return &KeyorixCore{storage: storagetest.Hooked(c.storage, &storagetest.StoreHooks{
		WrapTx: true,
		AssignPermissionToRole: func(next storage.Storage, ctx context.Context, roleID, permissionID uint) error {
			if attempted.Add(1) == 1 && failFirstGrant {
				return errors.New("injected grant failure")
			}
			return next.AssignPermissionToRole(ctx, roleID, permissionID)
		},
		SetSystemMetadata: func(next storage.Storage, ctx context.Context, key, value string) error {
			if key == rbacReconcilePendingRow && attempted.Load() > 0 {
				fired.Store(true)
				return errors.New("injected pending-row save failure")
			}
			return next.SetSystemMetadata(ctx, key, value)
		},
	})}, fired
}

func pendingRow(t *testing.T, c *KeyorixCore) string {
	t.Helper()
	raw, _, err := c.storage.GetSystemMetadata(context.Background(), rbacReconcilePendingRow)
	require.NoError(t, err)
	return raw
}

// TestReconcileRBAC_FinalSaveFailureThenRemoval: both grants land and every
// pending-row save after them fails. The row must not still list the landed
// pairs: an operator removal afterwards survives the next startup.
func TestReconcileRBAC_FinalSaveFailureThenRemoval(t *testing.T) {
	t.Parallel()
	c, db := newRBACReconcileCore(t)
	seedOldCatalog(t, c, db)
	ctx := context.Background()

	faulty, _ := failPendingSavesAfterGrant(c, false)
	require.NoError(t, faulty.ReconcileRBACPermissions(ctx))
	require.Equal(t, 2, connectReadHolders(t, c), "precondition: both grants landed")
	require.NotContains(t, pendingRow(t, c), "connect.read", "a landed pair is still listed after the post-grant save failed")

	removeConnectReadFrom(t, c, "system_admin")
	require.NoError(t, c.ReconcileRBACPermissions(ctx))
	require.False(t, roleHasPerm(t, c, "system_admin", "connect.read"), "operator removal undone after a failed final save")
	require.True(t, roleHasPerm(t, c, "admin", "connect.read"))
}

// TestReconcileRBAC_FinalSaveFailureAfterFailedGrantDropsPair: the first grant
// fails, the second lands, and recording the failed one for a retry fails too.
// The failed pair is dropped (fail closed: a missed baseline grant, logged),
// and the landed pair is not listed, so the operator's removal of it survives.
func TestReconcileRBAC_FinalSaveFailureAfterFailedGrantDropsPair(t *testing.T) {
	t.Parallel()
	c, db := newRBACReconcileCore(t)
	seedOldCatalog(t, c, db)
	ctx := context.Background()

	faulty, fired := failPendingSavesAfterGrant(c, true)
	require.NoError(t, faulty.ReconcileRBACPermissions(ctx))
	require.True(t, fired.Load(), "precondition: the save after the failed grant was refused")
	var holder, missed string
	for _, r := range []string{"admin", "system_admin"} {
		if roleHasPerm(t, c, r, "connect.read") {
			holder = r
		} else {
			missed = r
		}
	}
	require.NotEmpty(t, holder, "precondition: one grant landed")
	require.NotEmpty(t, missed, "precondition: one grant failed")

	removeConnectReadFrom(t, c, holder)
	require.NoError(t, c.ReconcileRBACPermissions(ctx))
	require.False(t, roleHasPerm(t, c, holder, "connect.read"), "operator removal from %s undone after a failed save", holder)
	require.False(t, roleHasPerm(t, c, missed, "connect.read"), "a pair whose retry could not be recorded is dropped, not granted")
	require.NotContains(t, pendingRow(t, c), "connect.read")
}

// TestReconcileRBAC_PreGrantSaveFailureGrantsNothing: the save that settles
// the owed pairs before their grants fails. Nothing is granted, both pairs
// stay owed, and the next clean startup grants them.
func TestReconcileRBAC_PreGrantSaveFailureGrantsNothing(t *testing.T) {
	t.Parallel()
	c, db := newRBACReconcileCore(t)
	seedOldCatalog(t, c, db)
	ctx := context.Background()

	// The settling save is the first pending-row write that no longer lists
	// connect.read after one that did (the debt record).
	var owed, fired atomic.Bool
	faulty := &KeyorixCore{storage: storagetest.Hooked(c.storage, &storagetest.StoreHooks{
		SetSystemMetadata: func(next storage.Storage, ctx context.Context, key, value string) error {
			if key == rbacReconcilePendingRow {
				if strings.Contains(value, "connect.read") {
					owed.Store(true)
				} else if owed.Load() && !fired.Load() {
					fired.Store(true)
					return errors.New("injected settling save failure")
				}
			}
			return next.SetSystemMetadata(ctx, key, value)
		},
	})}
	require.NoError(t, faulty.ReconcileRBACPermissions(ctx))
	require.True(t, fired.Load(), "precondition: the settling save was refused")
	require.Equal(t, 0, connectReadHolders(t, c), "a grant was attempted although its pair could not be settled first")
	require.Contains(t, pendingRow(t, c), "connect.read", "both pairs stay owed")

	require.NoError(t, c.ReconcileRBACPermissions(ctx))
	require.Equal(t, 2, connectReadHolders(t, c), "the next clean startup grants the owed pairs")
	require.NotContains(t, pendingRow(t, c), "connect.read")
}

// TestReconcileRBAC_NonBaselinePendingEntrySettled: a v2 entry naming a role
// that is not canonical, or a pair no canonical role definition lists, is
// dropped when the row is read, granted to nobody, and not carried forward
// (REVIEW-4560 L3).
func TestReconcileRBAC_NonBaselinePendingEntrySettled(t *testing.T) {
	t.Parallel()
	c, db := newRBACReconcileCore(t)
	seedOldCatalog(t, c, db)
	ctx := context.Background()
	require.NoError(t, c.ReconcileRBACPermissions(ctx))
	removeConnectReadFrom(t, c, "admin")

	require.NoError(t, c.storage.SetSystemMetadata(ctx, rbacReconcilePendingRow,
		`{"connect.read":["not_a_role","viewer"],"no.such.permission":["admin"]}`))
	require.NoError(t, c.ReconcileRBACPermissions(ctx))
	require.False(t, roleHasPerm(t, c, "viewer", "connect.read"), "a non-baseline pair was granted")
	require.False(t, roleHasPerm(t, c, "admin", "connect.read"), "an operator removal was undone")
	require.Equal(t, "{}", pendingRow(t, c), "non-baseline entries are settled, not kept forever")
}

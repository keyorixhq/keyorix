package core

// rbac_reconcile_pending_role_test.go — REVIEW-4542-M1: the pending-grants debt
// is owed per (permission, role), not per permission. A role that already
// received a pending permission is never re-granted it, even while another
// baseline role's grant keeps failing; an entry in the old per-permission
// format cannot say which roles were owed, so it grants nothing; and two
// reconciles in one process run one after the other, so one cannot re-save a
// debt the other already cleared.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// removeConnectReadFrom is the operator removing connect.read from role.
func removeConnectReadFrom(t *testing.T, c *KeyorixCore, role string) {
	t.Helper()
	ctx := context.Background()
	r, err := c.storage.GetRoleByName(ctx, role)
	require.NoError(t, err)
	perms, err := c.storage.ListPermissions(ctx)
	require.NoError(t, err)
	for _, p := range perms {
		if p.Name == "connect.read" {
			require.NoError(t, c.storage.RemovePermissionFromRole(ctx, r.ID, p.ID))
			return
		}
	}
	t.Fatal("connect.read does not exist")
}

func failFirstGrant() *faultstorage.FaultSpec {
	return &faultstorage.FaultSpec{
		Method: "AssignPermissionToRole", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected grant failure"),
	}
}

// TestReconcileRBAC_PendingRemovalFromGrantedRoleKept: connect.read is owed to
// admin and system_admin. The first grant fails, the second lands. The
// operator then removes connect.read from the role that received it, and the
// next startup's grant to the other role fails again. The removal must stay:
// only the role whose grant never landed is still owed.
func TestReconcileRBAC_PendingRemovalFromGrantedRoleKept(t *testing.T) {
	t.Parallel()
	c, db := newRBACReconcileCore(t)
	seedOldCatalog(t, c, db)
	ctx := context.Background()

	runReconcileWithFault(t, c, failFirstGrant())
	var holder, owed string
	for _, r := range []string{"admin", "system_admin"} {
		if roleHasPerm(t, c, r, "connect.read") {
			holder = r
		} else {
			owed = r
		}
	}
	require.NotEmpty(t, holder, "precondition: one baseline role received connect.read")
	require.NotEmpty(t, owed, "precondition: one baseline role's grant failed")

	removeConnectReadFrom(t, c, holder)

	// The owed role is first in grant order, so call 1 is its grant again.
	runReconcileWithFault(t, c, failFirstGrant())
	require.False(t, roleHasPerm(t, c, holder, "connect.read"), "operator removal from %s was undone while %s's grant was still failing", holder, owed)
	require.False(t, roleHasPerm(t, c, owed, "connect.read"), "precondition: the grant to %s failed again", owed)

	require.NoError(t, c.ReconcileRBACPermissions(ctx))
	require.True(t, roleHasPerm(t, c, owed, "connect.read"), "the role whose grant never landed still gets it")
	require.False(t, roleHasPerm(t, c, holder, "connect.read"), "operator removal from %s was undone", holder)
}

// TestReconcileRBAC_LegacyPendingEntryGrantsNothing: a pending entry written
// in the old per-permission format (rbac_reconcile_pending_grants_v1, a JSON
// list of names) does not say which roles were still owed, so a role without
// the permission may be one whose grant failed or one the operator stripped.
// It fails closed: the entry is dropped and nothing is granted from it.
func TestReconcileRBAC_LegacyPendingEntryGrantsNothing(t *testing.T) {
	t.Parallel()
	c, db := newRBACReconcileCore(t)
	seedOldCatalog(t, c, db)
	ctx := context.Background()

	require.NoError(t, c.ReconcileRBACPermissions(ctx))
	require.Equal(t, 2, connectReadHolders(t, c))
	removeConnectReadFrom(t, c, "admin")
	require.NoError(t, c.storage.SetSystemMetadata(ctx, "rbac_reconcile_pending_grants_v1", `["connect.read"]`))

	require.NoError(t, c.ReconcileRBACPermissions(ctx))
	require.False(t, roleHasPerm(t, c, "admin", "connect.read"), "a legacy pending entry re-granted a permission the operator removed")
	require.True(t, roleHasPerm(t, c, "system_admin", "connect.read"))
	raw, _, err := c.storage.GetSystemMetadata(ctx, "rbac_reconcile_pending_grants_v1")
	require.NoError(t, err)
	require.Equal(t, "[]", raw, "the legacy entry is dropped")

	require.NoError(t, c.ReconcileRBACPermissions(ctx))
	require.False(t, roleHasPerm(t, c, "admin", "connect.read"))
}

// TestReconcileRBAC_ConcurrentRunsSerialised: two reconciles over one store.
// The first pauses right after recording its debt; the second must not run
// while it is paused. Without serialisation the second clears the debt, the
// first then resumes and saves its stale copy, and a later startup re-grants
// a permission the operator removed in between.
// rbac_reconcile_lock_postgres_test.go runs the same with two replicas.
func TestReconcileRBAC_ConcurrentRunsSerialised(t *testing.T) {
	t.Parallel()
	c, db := newRBACReconcileCore(t)
	seedOldCatalog(t, c, db)
	requireReconcilesSerialised(t, c, c.storage, c.storage, db)
}

// requireReconcilesSerialised runs reconcile A over storeA, paused in its
// first SetSystemMetadata (the debt record, after it read the pending row),
// starts reconcile B over storeB, and requires that B does not ENTER the
// reconcile while A is paused, and that no stale debt survives. c reads the
// result. B signals entry from inside its WithNamedLock and from its first
// SetSystemMetadata (its debt record, which a run without the lock reaches at
// once), so the verdict does not depend on how long B's run takes once inside
// (REVIEW-4560 L1: on a loaded Postgres B could take longer than the old
// completion wait and pass unserialised).
func requireReconcilesSerialised(t *testing.T, c *KeyorixCore, storeA, storeB storage.Storage, db *gorm.DB) {
	t.Helper()
	ctx := context.Background()
	paused := make(chan struct{})
	resume := make(chan struct{})
	var once sync.Once
	replicaA := &KeyorixCore{storage: storagetest.Hooked(storeA, &storagetest.StoreHooks{
		SetSystemMetadata: func(next storage.Storage, ctx context.Context, key, value string) error {
			first := false
			once.Do(func() { first = true })
			if first {
				close(paused)
				<-resume
			}
			return next.SetSystemMetadata(ctx, key, value)
		},
	})}
	entered := make(chan struct{})
	var enterOnce sync.Once
	signalEntered := func() { enterOnce.Do(func() { close(entered) }) }
	replicaB := &KeyorixCore{storage: storagetest.Hooked(storeB, &storagetest.StoreHooks{
		WithNamedLock: func(next storage.Storage, ctx context.Context, lockKey string, fn func(ctx context.Context) error) error {
			return next.WithNamedLock(ctx, lockKey, func(ctx context.Context) error {
				signalEntered()
				return fn(ctx)
			})
		},
		SetSystemMetadata: func(next storage.Storage, ctx context.Context, key, value string) error {
			signalEntered()
			return next.SetSystemMetadata(ctx, key, value)
		},
	})}

	errA := make(chan error, 1)
	go func() { errA <- replicaA.ReconcileRBACPermissions(ctx) }()
	<-paused
	errB := make(chan error, 1)
	go func() { errB <- replicaB.ReconcileRBACPermissions(ctx) }()

	ranWhilePaused := false
	select {
	case <-entered:
		ranWhilePaused = true
	case <-time.After(2 * time.Second):
	}
	close(resume)
	require.False(t, ranWhilePaused, "a second reconcile ran while the first held its debt")
	require.NoError(t, <-errA)
	require.NoError(t, <-errB)

	require.Equal(t, 2, connectReadHolders(t, c))
	removeConnectReadFrom(t, c, "admin")
	require.NoError(t, c.ReconcileRBACPermissions(ctx))
	require.False(t, roleHasPerm(t, c, "admin", "connect.read"), "a stale debt saved by the paused run re-granted an operator removal")

	var n int64
	require.NoError(t, db.Model(&models.Permission{}).Where("name = ?", "connect.read").Count(&n).Error)
	require.Equal(t, int64(1), n)
}

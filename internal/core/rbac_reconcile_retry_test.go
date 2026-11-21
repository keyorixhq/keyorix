package core

// rbac_reconcile_retry_test.go — a baseline grant that fails during
// ReconcileRBACPermissions is retried on the next startup, and only then.
//
// Before the pending-grants row (rbacReconcilePendingRow) a failed grant was logged and forgotten: the
// next startup found the permission already existing, created nothing, and
// returned before granting anything, so the baseline role went without the
// permission until an operator granted it by hand. These tests drive the real
// reconcile twice over one database, faulting a storage call on the first run
// only (internal/faultstorage), and assert the second run lands the grant.
//
// What they do not cover: a crash between CreatePermission and the grants
// (same recovery path as a failed grant, since the name is listed before the
// create), and a failure to write the pending list itself (the run then stops
// before creating anything; nothing is lost but nothing is created either).

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
)

// connectReadHolders counts how many of connect.read's baseline roles
// (admin, system_admin) hold it.
func connectReadHolders(t *testing.T, c *KeyorixCore) int {
	t.Helper()
	n := 0
	for _, r := range []string{"admin", "system_admin"} {
		if roleHasPerm(t, c, r, "connect.read") {
			n++
		}
	}
	return n
}

func runReconcileWithFault(t *testing.T, c *KeyorixCore, spec *faultstorage.FaultSpec) {
	t.Helper()
	fs := faultstorage.NewFaultyStorage(c.storage, spec)
	faulty := &KeyorixCore{storage: fs}
	require.NoError(t, faulty.ReconcileRBACPermissions(context.Background()))
	require.True(t, fs.Fired(), "precondition: the fault must fire during the first reconcile (%s)", spec.Method)
}

func TestReconcileRBAC_FailedGrantRetriedNextStartup(t *testing.T) {
	t.Parallel()
	c, db := newRBACReconcileCore(t)
	seedOldCatalog(t, c, db)

	runReconcileWithFault(t, c, &faultstorage.FaultSpec{
		Method: "AssignPermissionToRole", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected grant failure"),
	})
	require.Equal(t, 1, connectReadHolders(t, c), "precondition: the faulted run granted connect.read to one baseline role, not both")

	require.NoError(t, c.ReconcileRBACPermissions(context.Background()))
	require.Equal(t, 2, connectReadHolders(t, c), "the next startup must land the grant the faulted run missed")
	require.False(t, roleHasPerm(t, c, "viewer", "connect.read"), "the retry grants only baseline roles")
}

func TestReconcileRBAC_RoleReadFailureRetriedNextStartup(t *testing.T) {
	t.Parallel()
	c, db := newRBACReconcileCore(t)
	seedOldCatalog(t, c, db)

	runReconcileWithFault(t, c, &faultstorage.FaultSpec{
		Method: "GetRolePermissions", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected role read failure"),
	})
	require.Less(t, connectReadHolders(t, c), 2, "precondition: the role whose read failed did not get connect.read")

	require.NoError(t, c.ReconcileRBACPermissions(context.Background()))
	require.Equal(t, 2, connectReadHolders(t, c), "the next startup must grant the role it could not read")
}

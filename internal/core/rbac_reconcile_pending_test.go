package core

// rbac_reconcile_pending_test.go — the pending-grants list
// (rbacReconcilePendingRow) behind the retry in rbac_reconcile_retry_test.go:
// what it holds while a grant is owed, and that a cleared entry is never
// re-granted.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestReconcileRBAC_CompletedGrantNotReappliedAfterOperatorRemoval: once every
// grant a new permission owes has landed, the permission is an existing one like
// any other. An operator who then removes the grant keeps it removed.
func TestReconcileRBAC_CompletedGrantNotReappliedAfterOperatorRemoval(t *testing.T) {
	t.Parallel()
	c, db := newRBACReconcileCore(t)
	seedOldCatalog(t, c, db)
	ctx := context.Background()

	require.NoError(t, c.ReconcileRBACPermissions(ctx))
	require.Equal(t, 2, connectReadHolders(t, c))
	raw, found, err := c.storage.GetSystemMetadata(ctx, rbacReconcilePendingRow)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "{}", raw, "nothing is owed after a clean run")

	admin, err := c.storage.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	var connectRead models.Permission
	require.NoError(t, db.Where("name = ?", "connect.read").First(&connectRead).Error)
	require.NoError(t, c.storage.RemovePermissionFromRole(ctx, admin.ID, connectRead.ID))

	require.NoError(t, c.ReconcileRBACPermissions(ctx))
	require.False(t, roleHasPerm(t, c, "admin", "connect.read"), "an operator removal after the grant completed is preserved")
}

// TestReconcileRBAC_PendingListedWhileGrantOwed: a permission with a failed
// grant stays on the pending list until a clean run clears it.
func TestReconcileRBAC_PendingListedWhileGrantOwed(t *testing.T) {
	t.Parallel()
	c, db := newRBACReconcileCore(t)
	seedOldCatalog(t, c, db)
	ctx := context.Background()

	runReconcileWithFault(t, c, &faultstorage.FaultSpec{
		Method: "AssignPermissionToRole", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected grant failure"),
	})
	raw, found, err := c.storage.GetSystemMetadata(ctx, rbacReconcilePendingRow)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, `{"connect.read":["admin"]}`, raw, "only the role whose grant failed is owed")

	require.NoError(t, c.ReconcileRBACPermissions(ctx))
	raw, _, err = c.storage.GetSystemMetadata(ctx, rbacReconcilePendingRow)
	require.NoError(t, err)
	require.Equal(t, "{}", raw)
}

// TestReconcileRBAC_PendingWriteFailureCreatesNothing: the list is written
// before any permission is created, so failing that write stops the run with
// nothing created, and the next run starts from the same state.
func TestReconcileRBAC_PendingWriteFailureCreatesNothing(t *testing.T) {
	t.Parallel()
	c, db := newRBACReconcileCore(t)
	seedOldCatalog(t, c, db)
	ctx := context.Background()

	fs := faultstorage.NewFaultyStorage(c.storage, &faultstorage.FaultSpec{
		Method: "SetSystemMetadata", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected metadata write failure"),
	})
	err := (&KeyorixCore{storage: fs}).ReconcileRBACPermissions(ctx)
	require.True(t, fs.Fired())
	require.Error(t, err)
	var n int64
	require.NoError(t, db.Model(&models.Permission{}).Where("name = ?", "connect.read").Count(&n).Error)
	require.Zero(t, n, "nothing is created when the debt cannot be recorded first")

	require.NoError(t, c.ReconcileRBACPermissions(ctx))
	require.Equal(t, 2, connectReadHolders(t, c))
}

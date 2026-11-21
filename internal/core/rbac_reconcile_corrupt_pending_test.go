package core

// rbac_reconcile_corrupt_pending_test.go — review L1 of REVIEW-4542-M1: an
// unreadable pending-grants row (rbac_reconcile_pending_grants_v2) must not
// stop the startup catalog top-up for good. It fails closed: the row is
// dropped, nothing is granted from it, and the rest of the reconcile runs.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestReconcileRBAC_CorruptPendingRowDroppedTopUpContinues: the install
// predates connect.platform.use, the operator removed connect.read from
// admin, and the v2 row is unreadable (and, read naively, would name that
// very pair). The startup must still create connect.platform.use and grant it
// to its baseline roles, must not give admin connect.read back, and must leave
// a readable row so the next startup does not trip on it again.
func TestReconcileRBAC_CorruptPendingRowDroppedTopUpContinues(t *testing.T) {
	t.Parallel()
	for name, corrupt := range map[string]string{
		"truncated":    `{"connect.read":["admin"]`,
		"wrong shape":  `{"connect.read":"admin"}`,
		"v1 list":      `["connect.read"]`,
		"not json":     `connect.read=admin`,
		"wrong member": `{"connect.read":[1]}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, db := newRBACReconcileCore(t)
			seedOldCatalogWithoutPlatformUse(t, c, db)
			ctx := context.Background()
			removeConnectReadFrom(t, c, "admin")
			require.NoError(t, c.storage.SetSystemMetadata(ctx, rbacReconcilePendingRow, corrupt))

			require.NoError(t, c.ReconcileRBACPermissions(ctx), "a corrupt pending row stopped the reconcile")
			require.True(t, roleHasPerm(t, c, "admin", "connect.platform.use"), "the catalog top-up did not run past the corrupt row")
			require.True(t, roleHasPerm(t, c, "system_admin", "connect.platform.use"))
			require.False(t, roleHasPerm(t, c, "viewer", "connect.platform.use"))
			require.False(t, roleHasPerm(t, c, "admin", "connect.read"), "a pair named by the corrupt row was granted")

			raw, found, err := c.storage.GetSystemMetadata(ctx, rbacReconcilePendingRow)
			require.NoError(t, err)
			require.True(t, found)
			var owed map[string][]string
			require.NoError(t, json.Unmarshal([]byte(raw), &owed), "the corrupt row was left in place")
			require.NotContains(t, owed, "connect.read")

			require.NoError(t, c.ReconcileRBACPermissions(ctx))
			require.False(t, roleHasPerm(t, c, "admin", "connect.read"))
		})
	}
}

// TestReconcileRBAC_CorruptPendingRowDroppedWithNothingMissing: the same with
// a complete catalog, the path that returns before any save. The corrupt row
// is still replaced, so it is logged once, not on every startup.
func TestReconcileRBAC_CorruptPendingRowDroppedWithNothingMissing(t *testing.T) {
	t.Parallel()
	c, db := newRBACReconcileCore(t)
	seedOldCatalog(t, c, db)
	ctx := context.Background()
	require.NoError(t, c.ReconcileRBACPermissions(ctx))
	removeConnectReadFrom(t, c, "admin")
	require.NoError(t, c.storage.SetSystemMetadata(ctx, rbacReconcilePendingRow, `{"connect.read":["admin"]`))

	require.NoError(t, c.ReconcileRBACPermissions(ctx))
	require.False(t, roleHasPerm(t, c, "admin", "connect.read"), "a pair named by the corrupt row was granted")
	raw, _, err := c.storage.GetSystemMetadata(ctx, rbacReconcilePendingRow)
	require.NoError(t, err)
	require.Equal(t, "{}", raw, "the corrupt row is dropped")
}

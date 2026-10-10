// role_permission_cache_cross_replica_postgres_test.go — proves the
// "principal permissions" cache (PERF-3, docs/specs/read-path-caching.md
// PR-2) is correct ACROSS replicas: a permission revoke committed by
// replica A must deny on replica B's very next RoleSetHasPermission call,
// even though B already has a warm "allowed" cache entry for that exact
// role-set+permission. Mirrors secret_metadata_cache_cross_replica_postgres_test.go's
// setup (two independent LocalStorage instances, two pools, one real
// Postgres schema migrated through the production entry point).
//
// Postgres only, skipped cleanly when KEYORIX_TEST_PG_DSN is unset.
package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestCrossReplica_RolePermissionCache_RevokeVisibleOnNextRead(t *testing.T) {
	t.Parallel()
	replicaA, replicaB := newRBACCrossReplicaPair(t)
	ctx := context.Background()

	roleName, err := identity.NewFoldedName("cr-role")
	require.NoError(t, err)
	role, err := replicaA.CreateRole(ctx, roleName, "")
	require.NoError(t, err)
	perm, err := replicaA.CreatePermission(ctx, &models.Permission{Name: "cr.permission"})
	require.NoError(t, err)
	require.NoError(t, replicaA.AssignPermissionToRole(ctx, role.ID, perm.ID))

	// Warm BOTH replicas' caches on the "allowed" decision.
	allowedA, err := replicaA.RoleSetHasPermission(ctx, []uint{role.ID}, "cr.permission")
	require.NoError(t, err)
	require.True(t, allowedA)
	allowedB, err := replicaB.RoleSetHasPermission(ctx, []uint{role.ID}, "cr.permission")
	require.NoError(t, err)
	require.True(t, allowedB)

	// Replica A revokes.
	require.NoError(t, replicaA.RemovePermissionFromRole(ctx, role.ID, perm.ID))

	// Replica B's VERY NEXT check must deny — no cross-process invalidation
	// call exists; the live generation check is the only mechanism.
	afterB, err := replicaB.RoleSetHasPermission(ctx, []uint{role.ID}, "cr.permission")
	require.NoError(t, err)
	require.False(t, afterB, "replica B served a stale pre-revoke ALLOWED decision from its own cache after replica A's committed revoke")
}

func TestCrossReplica_RolePermissionCache_GrantVisibleOnNextRead(t *testing.T) {
	t.Parallel()
	replicaA, replicaB := newRBACCrossReplicaPair(t)
	ctx := context.Background()

	roleName, err := identity.NewFoldedName("cr-role-grant")
	require.NoError(t, err)
	role, err := replicaA.CreateRole(ctx, roleName, "")
	require.NoError(t, err)
	perm, err := replicaA.CreatePermission(ctx, &models.Permission{Name: "cr.permission.grant"})
	require.NoError(t, err)

	// Warm B's cache on the "not yet granted" decision.
	beforeB, err := replicaB.RoleSetHasPermission(ctx, []uint{role.ID}, "cr.permission.grant")
	require.NoError(t, err)
	require.False(t, beforeB)

	require.NoError(t, replicaA.AssignPermissionToRole(ctx, role.ID, perm.ID))

	afterB, err := replicaB.RoleSetHasPermission(ctx, []uint{role.ID}, "cr.permission.grant")
	require.NoError(t, err)
	require.True(t, afterB, "replica B served a stale pre-grant DENIED decision from its own cache after replica A's committed grant")
}

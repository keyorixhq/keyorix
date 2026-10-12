// role_permission_cache_rollback_test.go — coordinator review of #2767,
// 2026-10-05: a ROLLED-BACK transaction must not be able to poison the shared
// read-path cache.
//
// The shape. WithTransaction hands fn a transaction-scoped LocalStorage that
// shares the parent's cache POINTER, and inside the transaction every query
// (the generation read included) runs through the transaction handle, so it
// sees UNCOMMITTED values. A cached read inside such a transaction therefore
// writes an uncommitted answer, stamped with an uncommitted generation, into a
// cache that outlives the transaction. If the transaction rolls back, that
// entry stays — and the moment a COMMITTED write reproduces the same
// generation value, the rolled-back answer validates and is served.
//
// For RoleSetHasPermission that is an authorization bypass, and it is not a
// coincidence that has to be waited for: the generation is now a monotonic
// integer, so a rolled-back bump N→N+1 is reproduced EXACTLY by the very next
// committed role_permissions write of any kind. Making the generation
// deterministic (which was the right fix for the fuzz-oracle failure) is what
// turned this from improbable into certain.
//
// Fix: a transaction-scoped LocalStorage never reads and never writes the
// shared cache — LocalStorage.cacheEnabled is set only by NewLocalStorage.
package store

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// TestRoleSetHasPermission_RolledBackGrantIsNotServedAfterAnUnrelatedCommit is
// the red/green case. Red on 19c6f068a: the final read returns true, i.e. a
// permission that was never committed authorizes.
func TestRoleSetHasPermission_RolledBackGrantIsNotServedAfterAnUnrelatedCommit(t *testing.T) {
	ls := newRolePermCacheTestStorage(t)
	ctx := context.Background()

	role, err := ls.CreateRole(ctx, mustFoldedName(t, "target-role"), "")
	require.NoError(t, err)
	perm, err := ls.CreatePermission(ctx, &models.Permission{Name: "secrets.read"})
	require.NoError(t, err)

	// A second, unrelated (role, permission) pair whose later grant is what
	// advances the generation to the same value the rolled-back one reached.
	otherRole, err := ls.CreateRole(ctx, mustFoldedName(t, "other-role"), "")
	require.NoError(t, err)
	otherPerm, err := ls.CreatePermission(ctx, &models.Permission{Name: "secrets.write"})
	require.NoError(t, err)

	// Baseline: the permission is genuinely NOT granted.
	allowed, err := ls.RoleSetHasPermission(ctx, []uint{role.ID}, "secrets.read")
	require.NoError(t, err)
	require.False(t, allowed)

	// A transaction grants it and resolves the check inside itself (which is
	// what would publish "allowed" into the shared cache, stamped with the
	// transaction's own uncommitted generation), then rolls back.
	sentinel := errors.New("roll back on purpose")
	txErr := ls.WithTransaction(ctx, func(tx storage.Storage) error {
		if err := tx.AssignPermissionToRole(ctx, role.ID, perm.ID); err != nil {
			return err
		}
		inTx, err := tx.RoleSetHasPermission(ctx, []uint{role.ID}, "secrets.read")
		if err != nil {
			return err
		}
		// Inside the transaction the grant is real and visible — that part is
		// correct, and read-your-own-writes must keep working.
		require.True(t, inTx, "the transaction must see its own uncommitted grant")
		return sentinel
	})
	require.ErrorIs(t, txErr, sentinel)

	// The grant really did roll back.
	var granted int64
	require.NoError(t, ls.db.Model(&models.RolePermission{}).
		Where("role_id = ? AND permission_id = ?", role.ID, perm.ID).Count(&granted).Error)
	require.Zero(t, granted, "the rolled-back grant must not be in the database")

	// Now a COMMITTED, unrelated role_permissions write advances the global
	// generation by exactly one — reproducing the value the rolled-back
	// transaction had already stamped its cache entry with.
	require.NoError(t, ls.AssignPermissionToRole(ctx, otherRole.ID, otherPerm.ID))

	allowed, err = ls.RoleSetHasPermission(ctx, []uint{role.ID}, "secrets.read")
	require.NoError(t, err)
	require.False(t, allowed,
		"a permission from a ROLLED-BACK transaction is authorizing: the uncommitted answer was cached under the uncommitted generation, and the next committed write reproduced that generation exactly")

	// Anti-vacuity: every assertion above is negative, so all of them hold if
	// the cache is simply off. otherRole genuinely HAS otherPerm, so the root
	// store must fill and hit for that pair.
	requireRootRolePermCacheFillsAndHits(t, ctx, ls, otherRole.ID, "secrets.write")
}

// TestRoleSetHasPermission_TransactionScopedStoreNeverTouchesTheSharedCache
// guards the mechanism rather than this one symptom: no read inside a
// transaction may write the shared cache, whether the transaction commits or
// rolls back. Pinning it directly means a future change that re-enables
// caching inside a transaction fails here even if it happens not to reproduce
// the exact generation collision above.
func TestRoleSetHasPermission_TransactionScopedStoreNeverTouchesTheSharedCache(t *testing.T) {
	ls := newRolePermCacheTestStorage(t)
	ctx := context.Background()
	role, err := ls.CreateRole(ctx, mustFoldedName(t, "r1"), "")
	require.NoError(t, err)
	perm, err := ls.CreatePermission(ctx, &models.Permission{Name: "secrets.read"})
	require.NoError(t, err)
	require.NoError(t, ls.AssignPermissionToRole(ctx, role.ID, perm.ID))

	key := rolePermKey([]uint{role.ID}, "secrets.read")
	// Start from a cold cache for this key.
	_, cached := ls.rolePermCache.get(key)
	require.False(t, cached)

	// A COMMITTING transaction, so this is not about rollback: the rule is that
	// a tx-scoped store never writes the shared cache at all.
	require.NoError(t, ls.WithTransaction(ctx, func(tx storage.Storage) error {
		allowed, err := tx.RoleSetHasPermission(ctx, []uint{role.ID}, "secrets.read")
		require.NoError(t, err)
		require.True(t, allowed, "the live join inside the transaction still answers correctly")
		return nil
	}))

	_, cached = ls.rolePermCache.get(key)
	require.False(t, cached,
		"a read inside a transaction populated the shared cache; it reads uncommitted rows under an uncommitted generation, so nothing it resolves may be published")

	// Anti-vacuity: the SAME read from the ROOT store must fill and hit, which
	// is what makes "the tx-scoped store did not" a fact about the transaction
	// rather than about the feature being off.
	requireRootRolePermCacheFillsAndHits(t, ctx, ls, role.ID, "secrets.read")
}

// requireRootRolePermCacheFillsAndHits is the positive control both tests in
// this file need (coordinator review of #2767, item 5).
//
// Both tests assert that something is NOT served from cache, and both would
// pass trivially with the cache disabled — if cacheEnabled were dropped, if the
// generation counter stopped advancing, if the feature were reverted outright.
// A test that cannot distinguish "the bug is fixed" from "the feature is gone"
// is not evidence for the fix.
//
// The hit is asserted through the real read-path predicate
// (getCachedRolePermission), not inferred from an entry being present: an entry
// whose generation check fails is present and useless, which is exactly the
// state a broken generation signal would leave behind.
func requireRootRolePermCacheFillsAndHits(t *testing.T, ctx context.Context, ls *LocalStorage, roleID uint, permission string) {
	t.Helper()
	allowed, err := ls.RoleSetHasPermission(ctx, []uint{roleID}, permission)
	require.NoError(t, err)
	require.True(t, allowed, "the control pair must genuinely be granted, or a false answer could be cached for the wrong reason")

	key := rolePermKey([]uint{roleID}, permission)
	_, filled := ls.rolePermCache.get(key)
	require.True(t, filled,
		"the root store did not FILL the role-permission cache — every not-served assertion in this file would pass with caching off")

	cachedAllowed, hit := ls.getCachedRolePermission(ctx, key)
	require.True(t, hit,
		"the root store filled the cache but cannot HIT it: the generation written on store does not validate on read, so the cache is dead weight and this file's negative assertions prove nothing")
	require.True(t, cachedAllowed, "the cached answer disagrees with the live one")
}

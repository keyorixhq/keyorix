// secret_node_cache_epoch_repair_first_postgres_test.go: REVIEW-3732-DEEP-2 F1.
// The cache-epoch repair commits before the invalidation, and a reading the
// repair cannot fix is invalidated once, not on every tick.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSecretNodeCacheEpochIntegrity_RepairCommitsWhenTheInvalidationCannotLockARow_Postgres
// (REVIEW-3732-DEEP-2 F1): the repair commits in its own transaction before
// the invalidation, so a row lock held elsewhere fails only the invalidation.
// The trigger is this release's from that tick on, and the next tick finishes
// the invalidation.
func TestSecretNodeCacheEpochIntegrity_RepairCommitsWhenTheInvalidationCannotLockARow_Postgres(t *testing.T) {
	shortRepairLockTimeout(t)
	w := newEpochIntegrityWorld(t)
	replaceCacheEpochBodyKeepingOldEpoch(t, w.db)
	w.setStatusDirect(t, w.db, "suspended")

	lock := w.db.Begin()
	require.NoError(t, lock.Error)
	require.NoError(t, lock.Exec("SELECT id FROM secret_nodes WHERE id = ? FOR UPDATE", w.created.ID).Error)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, err := w.c.check(ctx)
	cancel()
	require.NoError(t, lock.Rollback().Error)
	require.ErrorContains(t, err, "invalidate the", "premise: the invalidation cannot lock the row")
	st, err := readTriggerIntegrity(context.Background(), w.db, secretNodeCacheEpochIntegrityTarget)
	require.NoError(t, err)
	require.Empty(t, st.problem, "the repair committed although the invalidation failed")
	require.True(t, w.c.pending, "the invalidation is still owed")
	require.Equal(t, "active", w.status(t), "premise: the warm entry is not flushed yet")

	flushed, err := w.c.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed, "the next tick finishes the invalidation")
	require.Equal(t, "suspended", w.status(t))
	flushed, err = w.c.check(context.Background())
	require.NoError(t, err)
	require.False(t, flushed, "and then reads clean")
}

// TestSecretNodeCacheEpochIntegrity_NonOriginSessionInvalidatesOncePerReading_Postgres
// (REVIEW-3732-DEEP-2 F1): a session not in 'origin' cannot be repaired from
// the checker. It is reported every tick, but the full-table invalidation runs
// once for that reading, not on every tick.
func TestSecretNodeCacheEpochIntegrity_NonOriginSessionInvalidatesOncePerReading_Postgres(t *testing.T) {
	w := newEpochIntegrityWorld(t)
	sqlDB, err := w.db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1) // the check's reads and writes all run on the one session set below
	if err := w.db.Exec("SET session_replication_role = replica").Error; err != nil {
		t.Skipf("pg-gated: this role may not SET session_replication_role (needs a superuser or GRANT SET): %v", err)
	}
	epoch := nodeCacheEpoch(t, w.db, w.created.ID)
	flushed, err := w.c.check(context.Background())
	require.ErrorContains(t, err, "session_replication_role")
	require.True(t, flushed, "the first tick invalidates")
	require.Equal(t, epoch+1, nodeCacheEpoch(t, w.db, w.created.ID))
	for range 2 {
		flushed, err = w.c.check(context.Background())
		require.ErrorContains(t, err, "session_replication_role", "still reported every tick")
		require.False(t, flushed, "but not invalidated again for the same reading")
	}
	require.Equal(t, epoch+1, nodeCacheEpoch(t, w.db, w.created.ID))
	require.NoError(t, w.db.Exec("RESET session_replication_role").Error)
	flushed, err = w.c.check(context.Background())
	require.NoError(t, err, "back in origin: the owed state completes")
	require.True(t, flushed)
	flushed, err = w.c.check(context.Background())
	require.NoError(t, err)
	require.False(t, flushed)
}

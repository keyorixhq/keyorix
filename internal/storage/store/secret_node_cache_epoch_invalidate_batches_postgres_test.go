// secret_node_cache_epoch_invalidate_batches_postgres_test.go: REVIEW-3732-DEEP-2
// F1. The cache-epoch invalidation commits in batches that continue across ticks.
package store

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestSecretNodeCacheEpochIntegrity_InvalidationResumesAcrossTicks_Postgres
// (REVIEW-3732-DEEP-2 F1): the invalidation commits batch by batch and the
// next tick continues after the last committed one, so a table too large for
// one tick is still invalidated completely, and no row is moved twice.
func TestSecretNodeCacheEpochIntegrity_InvalidationResumesAcrossTicks_Postgres(t *testing.T) {
	shortRepairLockTimeout(t)
	oldBatch := secretNodeCacheEpochInvalidateBatch
	secretNodeCacheEpochInvalidateBatch = 2
	t.Cleanup(func() { secretNodeCacheEpochInvalidateBatch = oldBatch })
	w := newEpochIntegrityWorld(t)
	ids := []uint{w.created.ID}
	for i := range 4 {
		n, err := w.reader.CreateSecret(context.Background(), &models.SecretNode{
			Name: fmt.Sprintf("resume-%d", i), ProjectID: 1, EnvironmentID: 1, Status: "active",
		})
		require.NoError(t, err)
		ids = append(ids, n.ID)
	}
	slices.Sort(ids)
	replaceCacheEpochBodyKeepingOldEpoch(t, w.db)
	before := make([]int64, len(ids))
	for i, id := range ids {
		before[i] = nodeCacheEpoch(t, w.db, id)
	}

	// Rows 0-1 are the first batch; row 2 is locked, so the second fails.
	lock := w.db.Begin()
	require.NoError(t, lock.Error)
	require.NoError(t, lock.Exec("SELECT id FROM secret_nodes WHERE id = ? FOR UPDATE", ids[2]).Error)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	flushed, err := w.c.check(ctx)
	cancel()
	require.NoError(t, lock.Rollback().Error)
	require.ErrorContains(t, err, "continuing after id")
	require.True(t, flushed, "the first batch committed")
	for i, id := range ids {
		want := before[i]
		if i < 2 {
			want++
		}
		require.Equal(t, want, nodeCacheEpoch(t, w.db, id), "row %d after the first tick", i)
	}

	flushed, err = w.c.check(context.Background())
	require.NoError(t, err)
	require.True(t, flushed)
	for i, id := range ids {
		require.Equal(t, before[i]+1, nodeCacheEpoch(t, w.db, id), "row %d moved exactly once over both ticks", i)
	}
	flushed, err = w.c.check(context.Background())
	require.NoError(t, err)
	require.False(t, flushed, "the finished invalidation is the new baseline")
}

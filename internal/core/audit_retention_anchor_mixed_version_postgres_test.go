package core

// #3359, the mixed-version rollout seen from the core: an epoch-3+ replica's
// retention purge has written a v2 anchor (with the cumulative purged count),
// and a pre-#3258 replica that was already running when the database was
// migrated (the schema-epoch floor 3 only stops new starts) runs its own purge,
// which deletes rows and upserts a v1 anchor in one transaction. On PostgreSQL
// store.EnsureAuditRetentionAnchorTrigger refuses that upsert, so the whole
// purge rolls back: no row is deleted, the v2 anchor and its count survive, the
// chain verifies and a checkpoint still certifies chained + purged.
//
// The trigger tests in internal/storage write hand-made layout literals; this
// one drives the anchor value internal/core really writes (the trigger mirrors
// its "v2" + separator prefix by hand) and the v1 value the older purge wrote
// (auditRetentionAnchorValue), through the real store's transaction. The
// "without the trigger" case shows what the trigger prevents: the same older
// purge commits and the purged count is gone.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// preV2Purge is the retention purge of a binary from before #3258: it deletes
// the old rows and, in the same transaction, upserts a v1 anchor (no purged
// count) over whatever anchor is there.
func preV2Purge(ctx context.Context, c *KeyorixCore, cutoff time.Time) error {
	return c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		_, a, err := tx.DeleteAuditLogsBefore(ctx, cutoff)
		if err != nil || a == nil {
			return err
		}
		sig := c.signRetentionAnchorWithVersion(a.RowID, a.PrevHash, a.EntryHash, c.auditCkptKeyVersion)
		return tx.SetSystemMetadata(ctx, auditRetentionAnchorKey,
			auditRetentionAnchorValue(a.RowID, a.PrevHash, a.EntryHash, c.auditCkptKeyVersion, sig))
	})
}

func TestAuditRetentionAnchor_PreV2PurgeCannotDropThePurgedCount_Postgres(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T, trigger bool) (*purgeOvertakeEnv, string, int64) {
		t.Helper()
		db := pgOpen(t, pgIsolatedSchemaDSN(t, pgTestDSN(t)))
		env := newPurgeOvertakeEnv(t, db)
		if trigger {
			require.NoError(t, store.EnsureAuditRetentionAnchorTrigger(db))
		}
		res, err := env.c.PurgeAuditLogs(ctx, AuditLogRetentionConfig{RetentionDays: 30})
		require.NoError(t, err)
		require.Equal(t, int64(purgeOvertakeOld), res.DeletedCount)
		a, err := env.c.loadAuditRetentionAnchor(ctx)
		require.NoError(t, err)
		require.Equal(t, int64(purgeOvertakeOld), anchorPurgedEvents(a), "precondition: the current purge wrote a v2 anchor with the count")
		var rows int64
		require.NoError(t, db.Model(&models.AuditEvent{}).Count(&rows).Error)
		return env, retentionAnchorRaw(t, db), rows
	}
	// The older replica's purge reaches the two recent rows.
	cutoff := func(env *purgeOvertakeEnv) time.Time { return env.c.now().Add(-30 * time.Minute) }

	t.Run("the older purge rolls back whole and the count survives", func(t *testing.T) {
		env, anchorBefore, rowsBefore := setup(t, true)
		err := preV2Purge(ctx, env.c, cutoff(env))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refusing to replace the v2 audit retention anchor")
		var rows int64
		require.NoError(t, env.db.Model(&models.AuditEvent{}).Count(&rows).Error)
		assert.Equal(t, rowsBefore, rows, "the older purge's delete must roll back with its anchor write")
		assert.Equal(t, anchorBefore, retentionAnchorRaw(t, env.db))

		v, err := env.c.VerifyAuditChain(ctx)
		require.NoError(t, err)
		assert.True(t, v.Valid, v.Reason)
		cp, written, err := env.c.WriteAuditCheckpoint(ctx)
		require.NoError(t, err)
		require.True(t, written)
		// The two survivors and the purge event, plus the purged rows.
		assert.Equal(t, int64(purgeOvertakeNew+1+purgeOvertakeOld), cp.ChainedEvents)
	})
	t.Run("without the trigger the older purge drops the count", func(t *testing.T) {
		env, _, _ := setup(t, false)
		require.NoError(t, preV2Purge(ctx, env.c, cutoff(env)))
		a, err := env.c.loadAuditRetentionAnchor(ctx)
		require.NoError(t, err)
		require.NotNil(t, a, "the v1 anchor authenticates")
		assert.Zero(t, anchorPurgedEvents(a), "the cumulative purged count is lost: what the trigger prevents")
	})
}

func retentionAnchorRaw(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var m models.SystemMetadata
	require.NoError(t, db.Where("key = ?", auditRetentionAnchorKey).Take(&m).Error)
	return m.Value
}

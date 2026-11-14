package core

// AUDIT-WALK-TAILS-1 (#3944 follow-up): the two remaining from-the-start chain
// walks, the checkpoint write (writeAuditCheckpointLocked) and the accept-loss
// re-seal (resealAuditCheckpoint), go through walkAuditChainRacingPurge like
// VerifyAuditChain. A sanctioned retention purge that removes rows past the
// walk's cursor no longer makes them refuse a valid chain, and what they sign
// counts the moved anchor's purged events. A delete outside a purge in the same
// window still refuses.

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func testCheckpointWithPurgeOvertakingWalk(t *testing.T, open func(*testing.T) *gorm.DB) {
	ctx := context.Background()
	t.Run("a sanctioned purge in the window still writes the checkpoint", func(t *testing.T) {
		env := newPurgeOvertakeEnv(t, open(t))
		fired := env.purgeDuringWalk(t)
		cp, written, err := env.c.WriteAuditCheckpoint(ctx)
		require.NoError(t, err)
		require.True(t, fired.Load(), "test bug: the purge never ran inside the walk")
		require.True(t, written)
		// The survivors, the purge's own event and the purged rows (#3257).
		assert.Equal(t, int64(purgeOvertakeNew+1+purgeOvertakeOld), cp.ChainedEvents)
		v, err := env.c.VerifyAuditChain(ctx)
		require.NoError(t, err)
		assert.True(t, v.Valid, v.Reason)
		assert.Empty(t, v.CheckpointReason)
	})
	t.Run("a delete outside a purge in the window is refused", func(t *testing.T) {
		env := newPurgeOvertakeEnv(t, open(t))
		env.duringWalk(t, func() {
			require.NoError(t, env.db.Session(&gorm.Session{NewDB: true}).
				Exec(`DELETE FROM audit_events WHERE id < ?`, env.recent[0].ID).Error)
		})
		_, written, err := env.c.WriteAuditCheckpoint(ctx)
		require.ErrorIs(t, err, ErrAuditCheckpointRefused)
		assert.False(t, written)
		assert.Contains(t, err.Error(), "prev_hash does not link")
	})
}

func TestWriteAuditCheckpoint_PurgeOvertakingTheWalkStillWrites(t *testing.T) {
	testCheckpointWithPurgeOvertakingWalk(t, func(t *testing.T) *gorm.DB {
		db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
		require.NoError(t, err)
		return db
	})
}

func TestWriteAuditCheckpoint_PurgeOvertakingTheWalkStillWrites_Postgres(t *testing.T) {
	testCheckpointWithPurgeOvertakingWalk(t, func(t *testing.T) *gorm.DB {
		return pgOpen(t, pgIsolatedSchemaDSN(t, pgTestDSN(t)))
	})
}

// sealPurgeEnv is a purgeOvertakeEnv with a third recent row and a checkpoint
// over every row, then the middle recent row deleted (the loss to accept). It returns the planned
// acceptance; the walk hooks are registered by the caller after planning.
func sealPurgeEnv(t *testing.T, db *gorm.DB) (*purgeOvertakeEnv, *AuditLossPlan) {
	t.Helper()
	ctx := context.Background()
	env := newPurgeOvertakeEnv(t, db)
	env.recent = append(env.recent, logChainedEvent(t, env.c, "secret.read", env.c.now().Add(-time.Minute)))
	_, written, err := env.c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.True(t, written)
	require.NoError(t, env.db.Exec("DELETE FROM audit_events WHERE id = ?", env.recent[1].ID).Error)
	v, err := env.c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	require.False(t, v.Valid, "precondition: a deleted row reads broken")
	require.NotNil(t, v.FirstBrokenID)
	plan, err := env.c.PlanAuditLossAcceptance(ctx, sealReq(*v.FirstBrokenID))
	require.NoError(t, err)
	return env, plan
}

func testResealWithPurgeOvertakingWalk(t *testing.T, open func(*testing.T) *gorm.DB) {
	ctx := context.Background()
	t.Run("a sanctioned purge in the window still re-seals", func(t *testing.T) {
		env, plan := sealPurgeEnv(t, open(t))
		fired := env.purgeDuringWalk(t)
		res, err := env.c.AcceptAuditLoss(ctx, plan)
		require.NoError(t, err)
		require.True(t, fired.Load(), "test bug: the purge never ran inside the walk")
		// What survives (two of the three recent rows, the seal event and the
		// purge's event) plus the purged rows.
		assert.Equal(t, int64(purgeOvertakeNew+1-1+2+purgeOvertakeOld), res.Checkpoint.ChainedEvents)
		v, err := env.c.VerifyAuditChain(ctx)
		require.NoError(t, err)
		assert.True(t, v.Valid, v.Reason)
		assert.Equal(t, 1, v.Seals)
		assert.Empty(t, v.CheckpointReason)
	})
	t.Run("a delete outside a purge in the window is refused", func(t *testing.T) {
		env, plan := sealPurgeEnv(t, open(t))
		env.duringWalk(t, func() {
			require.NoError(t, env.db.Session(&gorm.Session{NewDB: true}).
				Exec(`DELETE FROM audit_events WHERE id < ?`, env.recent[0].ID).Error)
		})
		_, err := env.c.AcceptAuditLoss(ctx, plan)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "accept-loss: the sealed chain does not verify")
		assert.Contains(t, err.Error(), "prev_hash does not link")
	})
}

func TestAcceptAuditLoss_PurgeOvertakingTheResealWalkStillSeals(t *testing.T) {
	testResealWithPurgeOvertakingWalk(t, func(t *testing.T) *gorm.DB {
		db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
		require.NoError(t, err)
		return db
	})
}

func TestAcceptAuditLoss_PurgeOvertakingTheResealWalkStillSeals_Postgres(t *testing.T) {
	testResealWithPurgeOvertakingWalk(t, func(t *testing.T) *gorm.DB {
		return pgOpen(t, pgIsolatedSchemaDSN(t, pgTestDSN(t)))
	})
}

package core

// #3944, the rolling path: the chain-start segment of the rolling re-walk
// (advanceAuditRollingCycle, seg.AfterID == 0) goes through
// walkAuditChainRacingPurge too. A sanctioned purge that overtakes that
// segment's walk completes the cycle valid; a delete outside a purge in the
// same window records a broken full result.

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// rollingPurgeOvertakeEnv is a purgeOvertakeEnv with a signed checkpoint over
// every row and a one-segment rolling cycle, so the first segment is the chain
// start and its walk reaches past one store batch.
func rollingPurgeOvertakeEnv(t *testing.T, db *gorm.DB) *purgeOvertakeEnv {
	t.Helper()
	env := newPurgeOvertakeEnv(t, db)
	env.c.SetAuditIncrementalVerification(time.Hour, 1)
	_, written, err := env.c.WriteAuditCheckpoint(context.Background())
	require.NoError(t, err)
	require.True(t, written)
	return env
}

func rollingLastFull(t *testing.T, c *KeyorixCore) *auditFullResult {
	t.Helper()
	st, reason, err := c.loadAuditVerifyState(context.Background())
	require.NoError(t, err)
	require.Empty(t, reason)
	require.NotNil(t, st)
	require.NotNil(t, st.LastFull, "the one-segment cycle must record a full result")
	return st.LastFull
}

func testRollingCycleWithPurgeOvertakingWalk(t *testing.T, open func(*testing.T) *gorm.DB) {
	ctx := context.Background()
	t.Run("a sanctioned purge in the window completes the cycle valid", func(t *testing.T) {
		env := rollingPurgeOvertakeEnv(t, open(t))
		fired := env.purgeDuringWalk(t)
		res := &AuditVerifyTickResult{}
		require.NoError(t, env.c.advanceAuditRollingCycle(ctx, res))
		require.True(t, fired.Load(), "test bug: the purge never ran inside the walk")
		require.True(t, res.SegmentWalked)
		assert.True(t, res.CycleCompleted)
		full := rollingLastFull(t, env.c)
		assert.True(t, full.Valid, full.Reason)
		assert.Equal(t, auditFullSourceRolling, full.Source)
	})
	t.Run("a delete outside a purge in the window stays broken", func(t *testing.T) {
		env := rollingPurgeOvertakeEnv(t, open(t))
		fired := env.duringWalk(t, func() {
			require.NoError(t, env.db.Session(&gorm.Session{NewDB: true}).
				Exec(`DELETE FROM audit_events WHERE id < ?`, env.recent[0].ID).Error)
		})
		res := &AuditVerifyTickResult{}
		require.NoError(t, env.c.advanceAuditRollingCycle(ctx, res))
		require.True(t, fired.Load(), "test bug: the delete never ran inside the walk")
		assert.False(t, res.CycleCompleted)
		full := rollingLastFull(t, env.c)
		assert.False(t, full.Valid)
		assert.Contains(t, full.Reason, "prev_hash does not link")
	})
}

func TestAuditRollingCycle_PurgeOvertakingTheChainStartSegmentStaysValid(t *testing.T) {
	testRollingCycleWithPurgeOvertakingWalk(t, func(t *testing.T) *gorm.DB {
		db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
		require.NoError(t, err)
		return db
	})
}

func TestAuditRollingCycle_PurgeOvertakingTheChainStartSegmentStaysValid_Postgres(t *testing.T) {
	testRollingCycleWithPurgeOvertakingWalk(t, func(t *testing.T) *gorm.DB {
		return pgOpen(t, pgIsolatedSchemaDSN(t, pgTestDSN(t)))
	})
}

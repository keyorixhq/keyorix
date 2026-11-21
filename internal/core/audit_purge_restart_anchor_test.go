// audit_purge_restart_anchor_test.go — #4351: a sanctioned purge that empties
// the audit table (case 1) or removes the row the latest checkpoint certified
// as head (case 2) leaves the trail verifiable and checkpointable, on SQLite and
// PostgreSQL. The offline mirror and the negative cases are in
// internal/auditverify (purge_restart_anchor_test.go).
package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func assertAuditVerifies(t *testing.T, c *KeyorixCore, chained int64) {
	t.Helper()
	v, err := c.VerifyAuditChain(context.Background())
	require.NoError(t, err)
	require.True(t, v.Valid, v.Reason)
	assert.Equal(t, chained, v.ChainedEvents)
}

// Case 1: every event is older than the window; the purge empties the table
// before appending its own row.
func assertEmptyingPurgeVerifies(t *testing.T, c *KeyorixCore, fixed time.Time) {
	t.Helper()
	ctx := context.Background()
	for i := range 3 {
		logChainedEvent(t, c, "secret.read", fixed.AddDate(0, 0, -(40+i)))
	}
	cp, written, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.True(t, written)
	require.Equal(t, int64(3), cp.ChainedEvents)

	res, err := c.PurgeAuditLogs(ctx, AuditLogRetentionConfig{RetentionDays: 30})
	require.NoError(t, err)
	require.Equal(t, int64(3), res.DeletedCount)
	a, err := c.loadAuditRetentionAnchor(ctx)
	require.NoError(t, err)
	require.NotNil(t, a, "the purged count must be signed even though no row survived")
	assert.Empty(t, a.EntryHash, "a restart anchor names no surviving row")
	assert.Equal(t, int64(3), a.PurgedEvents)

	assertAuditVerifies(t, c, 1) // the system.audit_purge row
	cp2, written, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.True(t, written)
	assert.Equal(t, int64(4), cp2.ChainedEvents, "1 live + 3 purged")
	assertAuditVerifies(t, c, 1)
}

// Case 2: the checkpoint certifies the old events only; newer ones survive the
// purge, the certified head does not.
func assertPurgeOfCertifiedHeadVerifies(t *testing.T, c *KeyorixCore, fixed time.Time) {
	t.Helper()
	ctx := context.Background()
	for i := range 3 {
		logChainedEvent(t, c, "secret.read", fixed.AddDate(0, 0, -(42-i)))
	}
	cp, written, err := c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.True(t, written)
	for range 2 {
		logChainedEvent(t, c, "secret.updated", fixed.AddDate(0, 0, -1))
	}
	res, err := c.PurgeAuditLogs(ctx, AuditLogRetentionConfig{RetentionDays: 30})
	require.NoError(t, err)
	require.Equal(t, int64(3), res.DeletedCount)
	_, found, err := c.storage.AuditEntryHashByID(ctx, cp.HeadID)
	require.NoError(t, err)
	require.False(t, found, "premise: the purge removed the certified head")

	assertAuditVerifies(t, c, 3) // 2 survivors + the purge row
	// The tail check has no head row to start from: it reports the tail
	// unchecked rather than broken, and the scheduler's write falls back to the
	// full walk, which re-establishes a base.
	c.SetAuditIncrementalVerification(time.Hour, 0)
	r, err := c.VerifyAuditChainIncremental(ctx)
	require.NoError(t, err)
	assert.Nil(t, r.FirstBrokenID, r.Reason)
	assert.NotContains(t, r.Reason, "missing")
	assert.NotContains(t, r.CheckpointReason, "missing")

	cp2, written, err := c.WriteAuditCheckpointIncremental(ctx)
	require.NoError(t, err, "checkpointing must keep working after the certified head was purged")
	require.True(t, written)
	assert.Equal(t, int64(6), cp2.ChainedEvents, "3 live + 3 purged")
	// The incremental write also appends its verification-state event.
	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	require.True(t, v.Valid, v.Reason)
	r, err = c.VerifyAuditChainIncremental(ctx)
	require.NoError(t, err)
	assert.True(t, r.Valid, r.Reason)
}

func TestPurge4351_EmptyingPurge(t *testing.T) {
	t.Parallel()
	c, _, fixed := newReanchorTestCore(t)
	assertEmptyingPurgeVerifies(t, c, fixed)
}

func TestPurge4351_PurgeOfCertifiedHead(t *testing.T) {
	t.Parallel()
	c, _, fixed := newReanchorTestCore(t)
	assertPurgeOfCertifiedHeadVerifies(t, c, fixed)
}

func newPurge4351PostgresCore(t *testing.T) (*KeyorixCore, time.Time) {
	t.Helper()
	db := pgOpen(t, pgIsolatedSchemaDSN(t, pgTestDSN(t)))
	require.NoError(t, db.AutoMigrate(
		&models.AuditEvent{}, &models.AuditCheckpoint{}, &models.SystemMetadata{}, &models.LegalHold{},
	))
	fixed := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	c := NewKeyorixCore(store.NewLocalStorage(db))
	c.now = func() time.Time { return fixed }
	c.SetAuditCheckpointKey([]byte("reanchor-test-key-32-bytes-long"), "v1")
	return c, fixed
}

// The PostgreSQL variants: the purge runs under the KEYAUDIT advisory lock,
// ids come from a sequence, and the anchor is a text column.
func TestPurge4351_EmptyingPurge_Postgres(t *testing.T) {
	t.Parallel()
	c, fixed := newPurge4351PostgresCore(t)
	assertEmptyingPurgeVerifies(t, c, fixed)
}

func TestPurge4351_PurgeOfCertifiedHead_Postgres(t *testing.T) {
	t.Parallel()
	c, fixed := newPurge4351PostgresCore(t)
	assertPurgeOfCertifiedHeadVerifies(t, c, fixed)
}

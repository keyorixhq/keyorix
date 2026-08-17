// audit_chain_migrate_test.go — regression coverage for
// KeyorixCore.MigrateAuditChainEncoding (ADR-029 hash-format migration).
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrateAuditChainEncoding_Core_AppliesAndVerifiesAfterward(t *testing.T) {
	ctx := context.Background()
	c, db, fixed := newReanchorTestCore(t)

	e1 := logChainedEvent(t, c, "secret.read", fixed.AddDate(0, 0, -3))
	e2 := logChainedEvent(t, c, "secret.updated", fixed.AddDate(0, 0, -2))
	e3 := logChainedEvent(t, c, "secret.deleted", fixed.AddDate(0, 0, -1))

	// Simulate a legacy-encoded pre-existing chain by rewriting the stored
	// hashes directly, matching the storage-layer test's approach.
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("id = ?", e1.ID).
		Updates(map[string]interface{}{"entry_hash": "legacy-" + e1.EntryHash[:16]}).Error)
	var reload2, reload3 models.AuditEvent
	require.NoError(t, db.First(&reload2, e2.ID).Error)
	require.NoError(t, db.First(&reload3, e3.ID).Error)
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("id = ?", e2.ID).
		Updates(map[string]interface{}{"prev_hash": "legacy-" + e1.EntryHash[:16], "entry_hash": "legacy-" + e2.EntryHash[:16]}).Error)
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("id = ?", e3.ID).
		Updates(map[string]interface{}{"prev_hash": "legacy-" + e2.EntryHash[:16], "entry_hash": "legacy-" + e3.EntryHash[:16]}).Error)

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v.Valid, "sanity: legacy-encoded rows must not verify before migration")

	result, err := c.MigrateAuditChainEncoding(ctx, 1, false)
	require.NoError(t, err)
	assert.Equal(t, int64(3), result.RowsMigrated)
	assert.NotEmpty(t, result.HeadHash)

	v2, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v2.Valid, "chain must verify after a real migration run: %s", v2.Reason)

	// A completion event was appended, chained under the new encoding —
	// becoming the chain's fresh head.
	var head models.AuditEvent
	require.NoError(t, db.Order("id DESC").First(&head).Error)
	assert.Equal(t, "audit.chain_migrated", head.EventType)
	assert.Equal(t, head.ID, v2.HeadID, "the completion event itself must verify as the new head")
}

func TestMigrateAuditChainEncoding_Core_DryRunPersistsNothing(t *testing.T) {
	ctx := context.Background()
	c, db, fixed := newReanchorTestCore(t)

	e1 := logChainedEvent(t, c, "secret.read", fixed.AddDate(0, 0, -1))
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("id = ?", e1.ID).
		Updates(map[string]interface{}{"entry_hash": "legacy-" + e1.EntryHash[:16]}).Error)

	var before models.AuditEvent
	require.NoError(t, db.First(&before, e1.ID).Error)

	result, err := c.MigrateAuditChainEncoding(ctx, 1, true)
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.RowsMigrated, "dry run still reports what would change")

	var after models.AuditEvent
	require.NoError(t, db.First(&after, e1.ID).Error)
	assert.Equal(t, before.EntryHash, after.EntryHash, "dry run must not persist row changes")

	// No completion event is appended on a dry run — nothing to record.
	var count int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", "audit.chain_migrated").Count(&count).Error)
	assert.Equal(t, int64(0), count, "a dry run must not append a completion audit event")
}

// TestMigrateAuditChainEncoding_Core_ReSignsAnchorAfterPurge covers the
// interaction with a preceding retention purge: the earliest surviving row
// carries an anchor (its real predecessor was purged). A real migration run
// must re-sign that anchor with the row's newly computed hash so
// VerifyAuditChain (which authenticates the anchor against the signing key)
// keeps accepting it after the migration.
func TestMigrateAuditChainEncoding_Core_ReSignsAnchorAfterPurge(t *testing.T) {
	ctx := context.Background()
	c, db, fixed := newReanchorTestCore(t)

	for i := 0; i < 3; i++ {
		logChainedEvent(t, c, "secret.read", fixed.AddDate(0, 0, -(40+i)))
	}
	for i := 0; i < 2; i++ {
		logChainedEvent(t, c, "secret.updated", fixed.AddDate(0, 0, -1))
	}

	_, err := c.PurgeAuditLogs(ctx, AuditLogRetentionConfig{RetentionDays: 30})
	require.NoError(t, err)

	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	require.True(t, v.Valid, "sanity: purge alone must not break verification")

	// Simulate the anchored (earliest surviving) row being legacy-encoded:
	// rewrite its entry_hash directly (its prev_hash — the anchor's PrevHash —
	// must stay untouched, since it represents an already-purged predecessor).
	var earliest models.AuditEvent
	require.NoError(t, db.Where("event_type != ?", "system.audit_purge").Order("id ASC").First(&earliest).Error)
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("id = ?", earliest.ID).
		Updates(map[string]interface{}{"entry_hash": "legacy-" + earliest.EntryHash[:16]}).Error)

	v2, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.False(t, v2.Valid, "sanity: legacy-encoded anchored row must not verify before migration")

	result, err := c.MigrateAuditChainEncoding(ctx, 1, false)
	require.NoError(t, err)
	require.Equal(t, earliest.ID, result.AnchorRowID, "the anchored row must be reported for re-signing")
	assert.NotEmpty(t, result.AnchorNewEntryHash)

	v3, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v3.Valid, "chain must verify after the anchor is re-signed by the migration: %s", v3.Reason)
}

package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// appendLegacyEncodedEvent inserts a row already stored with a hash chain,
// then rewrites its prev_hash/entry_hash to simulate a row that was chained
// under a DIFFERENT (older) encoding than computeAuditEntryHash currently
// produces — exactly the state MigrateAuditChainEncoding exists to repair.
func appendLegacyEncodedEvent(t *testing.T, ls *LocalStorage, desc string, at time.Time, prevHash string) *models.AuditEvent {
	t.Helper()
	e := appendEvent(t, ls, "secret.read", desc, at)
	legacyEntryHash := "legacy-" + e.EntryHash[:16]
	require.NoError(t, ls.db.Model(&models.AuditEvent{}).Where("id = ?", e.ID).
		Updates(map[string]interface{}{"prev_hash": prevHash, "entry_hash": legacyEntryHash}).Error)
	e.PrevHash = prevHash
	e.EntryHash = legacyEntryHash
	return e
}

func TestMigrateAuditChainEncoding_RechainsUnderCurrentEncoding(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()

	e1 := appendLegacyEncodedEvent(t, ls, "first", base, auditGenesisHash)
	e2 := appendLegacyEncodedEvent(t, ls, "second", base.Add(time.Second), e1.EntryHash)
	e3 := appendLegacyEncodedEvent(t, ls, "third", base.Add(2*time.Second), e2.EntryHash)

	// Sanity: as stored, the chain does NOT verify under the current encoding.
	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.False(t, v.Valid, "legacy-encoded rows must not verify under the current encoding before migration")

	result, err := ls.MigrateAuditChainEncoding(context.Background(), false, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(3), result.RowsMigrated)
	assert.Equal(t, int64(0), result.UnchainedRowsSkipped)
	assert.Equal(t, e3.ID, result.HeadID)
	assert.NotEmpty(t, result.HeadHash)
	assert.Equal(t, uint(0), result.AnchorRowID, "no anchor supplied, none should be reported")

	v2, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.True(t, v2.Valid, "chain must verify under the current encoding after migration: %s", v2.Reason)
	assert.Equal(t, int64(3), v2.ChainedEvents)
	assert.Equal(t, result.HeadHash, v2.HeadHash)
	assert.Equal(t, result.HeadID, v2.HeadID)
}

func TestMigrateAuditChainEncoding_DryRunMakesNoChanges(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()

	e1 := appendLegacyEncodedEvent(t, ls, "first", base, auditGenesisHash)
	e2 := appendLegacyEncodedEvent(t, ls, "second", base.Add(time.Second), e1.EntryHash)

	result, err := ls.MigrateAuditChainEncoding(context.Background(), true, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.RowsMigrated, "dry run still computes what WOULD change")
	assert.NotEmpty(t, result.HeadHash)

	// Nothing was actually persisted: the stored rows are unchanged, and the
	// chain still fails verification exactly as before the call.
	var stored1, stored2 models.AuditEvent
	require.NoError(t, ls.db.First(&stored1, e1.ID).Error)
	require.NoError(t, ls.db.First(&stored2, e2.ID).Error)
	assert.Equal(t, e1.EntryHash, stored1.EntryHash, "dry run must not persist row 1")
	assert.Equal(t, e2.EntryHash, stored2.EntryHash, "dry run must not persist row 2")

	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.False(t, v.Valid, "chain must still fail verification after a dry run")
}

func TestMigrateAuditChainEncoding_LeavesUnchainedLegacyPrefixAlone(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()

	// Two pre-ADR-029 rows: no hash chain at all (empty entry_hash).
	tr := true
	for i, d := range []string{"unchained-1", "unchained-2"} {
		require.NoError(t, ls.db.Create(&models.AuditEvent{
			EventType: "secret.read", Description: d, Success: &tr,
			EventTime: base.Add(time.Duration(i) * time.Second), ActorType: "user",
		}).Error)
	}
	c1 := appendLegacyEncodedEvent(t, ls, "chained-1", base.Add(10*time.Second), auditGenesisHash)
	_ = appendLegacyEncodedEvent(t, ls, "chained-2", base.Add(11*time.Second), c1.EntryHash)

	result, err := ls.MigrateAuditChainEncoding(context.Background(), false, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.RowsMigrated, "only the chained rows are migrated")
	assert.Equal(t, int64(2), result.UnchainedRowsSkipped, "the unchained legacy prefix is left untouched")

	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.True(t, v.Valid, "chain must verify after migration: %s", v.Reason)
	assert.Equal(t, int64(2), v.UnchainedEvents)
	assert.Equal(t, int64(2), v.ChainedEvents)
}

// TestMigrateAuditChainEncoding_ReSignsRetentionAnchor covers the interaction
// with a retention purge that ran BEFORE the migration: the earliest
// surviving row's prev_hash is a non-genesis anchor value (its real
// predecessor was purged and can never be recomputed under any encoding).
// The migration must recompute that row's entry_hash under the current
// encoding while leaving its prev_hash exactly as the anchor says, and
// report it back to the caller so the anchor itself can be re-signed.
func TestMigrateAuditChainEncoding_ReSignsRetentionAnchor(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()

	const purgedPredecessorHash = "purged-predecessor-hash"
	anchored := appendLegacyEncodedEvent(t, ls, "first-surviving", base, purgedPredecessorHash)
	_ = appendLegacyEncodedEvent(t, ls, "second", base.Add(time.Second), anchored.EntryHash)

	anchor := &storage.AuditChainAnchor{
		RowID:     anchored.ID,
		PrevHash:  purgedPredecessorHash,
		EntryHash: anchored.EntryHash,
	}

	result, err := ls.MigrateAuditChainEncoding(context.Background(), false, anchor)
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.RowsMigrated)
	require.Equal(t, anchored.ID, result.AnchorRowID, "the earliest migrated row must be reported for anchor re-signing")
	assert.NotEmpty(t, result.AnchorNewEntryHash)
	assert.NotEqual(t, anchored.EntryHash, result.AnchorNewEntryHash, "the anchor row's hash changed under the new encoding")

	var stored models.AuditEvent
	require.NoError(t, ls.db.First(&stored, anchored.ID).Error)
	assert.Equal(t, purgedPredecessorHash, stored.PrevHash, "the purged predecessor's hash is preserved verbatim, not recomputed")
	assert.Equal(t, result.AnchorNewEntryHash, stored.EntryHash)

	// A re-signed anchor (matching what the caller is expected to persist)
	// must let the migrated chain verify from that point forward.
	newAnchor := &storage.AuditChainAnchor{
		RowID:     anchored.ID,
		PrevHash:  purgedPredecessorHash,
		EntryHash: result.AnchorNewEntryHash,
	}
	v, err := ls.VerifyAuditChain(context.Background(), newAnchor)
	require.NoError(t, err)
	assert.True(t, v.Valid, "chain must verify against the re-signed anchor: %s", v.Reason)
}

func TestMigrateAuditChainEncoding_Empty(t *testing.T) {
	ls := newAuditChainTestStore(t)
	result, err := ls.MigrateAuditChainEncoding(context.Background(), false, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(0), result.RowsMigrated)
	assert.Equal(t, int64(0), result.UnchainedRowsSkipped)
	assert.Equal(t, uint(0), result.HeadID)
}

func TestMigrateAuditChainEncoding_AlreadyCurrentEncodingIsIdempotent(t *testing.T) {
	ls := newAuditChainTestStore(t)
	base := time.Now().UTC()
	appendEvent(t, ls, "auth.login", "first", base)
	appendEvent(t, ls, "secret.read", "second", base.Add(time.Second))

	// Rows already chained under the CURRENT encoding: migration should be a
	// no-op in effect (same hashes recomputed) and the chain stays valid.
	result, err := ls.MigrateAuditChainEncoding(context.Background(), false, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.RowsMigrated, "rows are re-walked and rewritten even if already current")

	v, err := ls.VerifyAuditChain(context.Background(), nil)
	require.NoError(t, err)
	assert.True(t, v.Valid, "re-migrating already-current rows must not break the chain: %s", v.Reason)
}

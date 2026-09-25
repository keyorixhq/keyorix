package auditverify_test

// TestExhaustiveByteTamper_* extend TestDifferential_TamperMatrix's
// representative tamper shapes (differential_test.go) to full byte-level
// exhaustiveness: for each targeted column, EVERY byte offset is flipped,
// one at a time, and auditverify.Verify must never report VALID. This is the
// literal property design §9 (and the offline-fuzz coverage track) asks for
// — "verify-audit never returns VALID on tampered input" — rather than a
// sample of hand-picked tamper shapes.
//
// Each byte is flipped via XOR 0x01 (not 0xFF): every stored value tested
// here (hex-encoded hashes/signatures, and this fixture's own ASCII
// descriptions) has its high bit clear, so flipping only the low bit both
// guarantees a different byte value and keeps the result valid UTF-8 —
// avoiding a UTF-8-validity failure in the driver from masking the actual
// property under test.
//
// A tampered row's own prev_hash is a deliberate exception: flipping the
// FIRST (genesis) row's prev_hash is indistinguishable, to a bare walk with
// no retention-anchor key, from a legitimately sanctioned retention gap —
// walkChain's own documented behavior (verify.go) is to report that case
// INDETERMINATE, not BROKEN. Asserting Verdict != VerdictValid (rather than
// == VerdictBroken) is therefore the correct property, not a looser one: it
// is exactly what "never returns VALID on tampered input" means, and it
// still fails the test if a tamper were ever silently accepted as VALID.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/auditverify"
)

// tamperEveryByte reads the current value of a single column/row via readSQL
// (parameterized by id), then for every byte offset in that value: flips the
// byte, applies updateSQL (parameterized by the mutated value then id),
// asserts auditverify.Verify never reports VALID against the resulting file,
// and restores the original value before moving to the next offset.
func tamperEveryByte(t *testing.T, f *diffFixture, opts auditverify.Options, readSQL, updateSQL, label string, id any) {
	t.Helper()

	var orig string
	require.NoError(t, f.db.Raw(readSQL, id).Scan(&orig).Error)
	require.NotEmpty(t, orig, "fixture bug: %s is empty — nothing to tamper", label)

	origBytes := []byte(orig)
	for i := range origBytes {
		mutated := append([]byte(nil), origBytes...)
		mutated[i] ^= 0x01
		require.NotEqual(t, origBytes[i], mutated[i], "fixture bug: byte %d did not change", i)

		f.exec(updateSQL, string(mutated), id)

		db, err := auditverify.OpenSQLiteReadOnly(f.path)
		require.NoError(t, err)
		got, err := auditverify.Verify(f.ctx, db, opts)
		require.NoError(t, err)
		require.NoError(t, db.Close())

		require.NotEqual(t, auditverify.VerdictValid, got.Verdict,
			"%s byte %d: single-byte tamper went undetected (reason: %q)", label, i, got.Reason)

		f.exec(updateSQL, orig, id)
	}
}

// TestExhaustiveByteTamper_AuditRowDescription proves every single-byte
// tamper of a stored audit_events.description value is caught.
func TestExhaustiveByteTamper_AuditRowDescription(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(6, time.Hour)

	for id := uint64(1); id <= 6; id++ {
		tamperEveryByte(t, f, auditverify.Options{},
			"SELECT description FROM audit_events WHERE id = ?",
			"UPDATE audit_events SET description = ? WHERE id = ?",
			"audit_events.description", id)
	}
}

// TestExhaustiveByteTamper_AuditRowHashFields proves every single-byte
// tamper of a stored audit_events.prev_hash or entry_hash value is caught
// (never reported VALID — see the genesis-row exception noted above).
func TestExhaustiveByteTamper_AuditRowHashFields(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(6, time.Hour)

	for id := uint64(1); id <= 6; id++ {
		tamperEveryByte(t, f, auditverify.Options{},
			"SELECT prev_hash FROM audit_events WHERE id = ?",
			"UPDATE audit_events SET prev_hash = ? WHERE id = ?",
			"audit_events.prev_hash", id)
		tamperEveryByte(t, f, auditverify.Options{},
			"SELECT entry_hash FROM audit_events WHERE id = ?",
			"UPDATE audit_events SET entry_hash = ? WHERE id = ?",
			"audit_events.entry_hash", id)
	}
}

// TestExhaustiveByteTamper_CheckpointSignature proves every single-byte
// tamper of a stored audit_checkpoints.signature value is caught once a
// checkpoint signing key is supplied.
func TestExhaustiveByteTamper_CheckpointSignature(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(4, time.Hour)
	_, written, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	require.True(t, written)

	var cpID int64
	require.NoError(t, f.db.Raw("SELECT id FROM audit_checkpoints ORDER BY id DESC LIMIT 1").Scan(&cpID).Error)

	tamperEveryByte(t, f, auditverify.Options{CheckpointKey: fixedCheckpointKey},
		"SELECT signature FROM audit_checkpoints WHERE id = ?",
		"UPDATE audit_checkpoints SET signature = ? WHERE id = ?",
		"audit_checkpoints.signature", cpID)
}

// TestExhaustiveByteTamper_CheckpointHeadHash proves every single-byte
// tamper of a stored audit_checkpoints.head_hash value is caught once a
// checkpoint signing key is supplied.
func TestExhaustiveByteTamper_CheckpointHeadHash(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(4, time.Hour)
	_, written, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	require.True(t, written)

	var cpID int64
	require.NoError(t, f.db.Raw("SELECT id FROM audit_checkpoints ORDER BY id DESC LIMIT 1").Scan(&cpID).Error)

	tamperEveryByte(t, f, auditverify.Options{CheckpointKey: fixedCheckpointKey},
		"SELECT head_hash FROM audit_checkpoints WHERE id = ?",
		"UPDATE audit_checkpoints SET head_hash = ? WHERE id = ?",
		"audit_checkpoints.head_hash", cpID)
}

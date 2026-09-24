package auditverify

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedEmptySchema creates the three tables this package reads from, with no
// rows, at path — using plain DDL rather than gorm/models (this test file
// lives in package auditverify itself, so it stays inside the same
// no-core/no-storage independence boundary the dependency-guard test
// enforces for the non-test files).
func seedEmptySchema(t *testing.T, path string) {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer func() { _ = sqlDB.Close() }()

	for _, stmt := range []string{
		`CREATE TABLE audit_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_type TEXT,
			user_id INTEGER,
			secret_node_id INTEGER,
			project_id INTEGER,
			ip_address TEXT,
			description TEXT,
			success BOOLEAN,
			event_time DATETIME,
			diff TEXT,
			impersonated_by INTEGER,
			acting_as INTEGER,
			impersonation BOOLEAN,
			actor_type TEXT,
			machine_identity_id INTEGER,
			prev_hash TEXT,
			entry_hash TEXT
		)`,
		`CREATE TABLE audit_checkpoints (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			chained_events INTEGER,
			head_id INTEGER,
			head_hash TEXT,
			key_version TEXT,
			signature TEXT,
			anchor_token BLOB,
			anchored_at DATETIME,
			anchor_provider TEXT,
			created_at DATETIME
		)`,
		`CREATE TABLE system_metadata (
			key TEXT PRIMARY KEY,
			value TEXT,
			updated_at DATETIME
		)`,
	} {
		_, err := sqlDB.Exec(stmt)
		require.NoError(t, err)
	}
}

// TestCheckpointCanonical_ExactByteFormat locks checkpointCanonical's byte
// layout against internal/core.checkpointCanonical's own documented format
// ("v1\x00%d\x00%d\x00%s\x00%s" over ChainedEvents, HeadID, HeadHash,
// KeyVersion) — since that function is unexported, this package cannot call
// it directly to compare; this test instead pins the format by construction
// so any accidental drift here fails loudly rather than silently producing
// a signature that happens to never verify against a real server.
func TestCheckpointCanonical_ExactByteFormat(t *testing.T) {
	cp := &Checkpoint{ChainedEvents: 42, HeadID: 7, HeadHash: "abc123", KeyVersion: "v1"}
	got := checkpointCanonical(cp)
	want := "v1\x0042\x007\x00abc123\x00v1"
	assert.Equal(t, want, got)
}

// TestRetentionAnchorCanonical_ExactByteFormat mirrors the above for
// internal/core.auditRetentionAnchorCanonical's documented
// "retanchor-v1\x00%d\x00%s\x00%s\x00%s" format.
func TestRetentionAnchorCanonical_ExactByteFormat(t *testing.T) {
	got := retentionAnchorCanonical(9, "prevhash", "entryhash", "v1")
	want := "retanchor-v1\x009\x00prevhash\x00entryhash\x00v1"
	assert.Equal(t, want, got)
}

func TestParseHighWater_RoundTrip(t *testing.T) {
	cp := &Checkpoint{ChainedEvents: 100, HeadID: 55, HeadHash: "deadbeef", KeyVersion: "v1"}
	key := []byte("test-key-0123456789012345678901")
	sig := SignCheckpoint(cp, key)
	val := "v1" + auditHighWaterSep + "100" + auditHighWaterSep + "55" + auditHighWaterSep + "deadbeef" + auditHighWaterSep + "v1" + auditHighWaterSep + sig

	got, gotSig, ok := ParseHighWater(val)
	require.True(t, ok)
	assert.Equal(t, sig, gotSig)
	assert.Equal(t, cp.ChainedEvents, got.ChainedEvents)
	assert.Equal(t, cp.HeadID, got.HeadID)
	assert.Equal(t, cp.HeadHash, got.HeadHash)
	assert.Equal(t, cp.KeyVersion, got.KeyVersion)
	assert.True(t, HighWaterSigMatches(got, gotSig, key))
}

func TestParseHighWater_Malformed(t *testing.T) {
	for _, bad := range []string{"", "v2\x1f1\x1f2\x1f3\x1f4\x1f5", "v1\x1fnot-a-number\x1f2\x1f3\x1f4\x1f5", "garbage"} {
		_, _, ok := ParseHighWater(bad)
		assert.False(t, ok, "expected %q to be rejected as malformed", bad)
	}
}

func TestParseRetentionAnchor_RoundTrip(t *testing.T) {
	key := []byte("test-key-0123456789012345678901")
	sig := SignRetentionAnchor(3, "prev", "entry", "v1", key)
	val := "v1" + auditRetentionAnchorSep + "3" + auditRetentionAnchorSep + "prev" + auditRetentionAnchorSep + "entry" + auditRetentionAnchorSep + "v1" + auditRetentionAnchorSep + sig

	rowID, prevHash, entryHash, keyVersion, gotSig, ok := ParseRetentionAnchor(val)
	require.True(t, ok)
	assert.Equal(t, uint64(3), rowID)
	assert.Equal(t, "prev", prevHash)
	assert.Equal(t, "entry", entryHash)
	assert.Equal(t, "v1", keyVersion)
	assert.Equal(t, sig, gotSig)
	assert.True(t, RetentionAnchorSigMatches(rowID, prevHash, entryHash, keyVersion, gotSig, key))
}

func TestParseRetentionAnchor_ZeroRowIDRejected(t *testing.T) {
	// rowID == 0 is explicitly invalid (mirrors internal/core.parseAuditRetentionAnchor):
	// row ids start at 1, so a zero here can only be a malformed/forged value.
	val := "v1\x1f0\x1fprev\x1fentry\x1fv1\x1fsig"
	_, _, _, _, _, ok := ParseRetentionAnchor(val)
	assert.False(t, ok)
}

// TestNonNegativeUint64_RejectsNegative proves a negative signed column
// value errors instead of silently wrapping around to a huge uint64 (the
// gosec G115 class of bug) — a corrupted or adversarially crafted DB file
// with e.g. user_id = -1 must surface as a decode error, not a fabricated
// large id.
func TestNonNegativeUint64_RejectsNegative(t *testing.T) {
	_, err := nonNegativeUint64(sql.NullInt64{Int64: -1, Valid: true}, "user_id")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "negative")

	v, err := nonNegativeUint64(sql.NullInt64{Int64: 42, Valid: true}, "user_id")
	require.NoError(t, err)
	require.NotNil(t, v)
	assert.Equal(t, uint64(42), *v)

	v, err = nonNegativeUint64(sql.NullInt64{Valid: false}, "user_id")
	require.NoError(t, err)
	assert.Nil(t, v)
}

// TestVerify_EmptyDB proves an empty audit_events table verifies as VALID
// with zero counts, not an error or a spurious BROKEN — the base case every
// other behavior in this package builds on.
func TestVerify_EmptyDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.db")
	seedEmptySchema(t, path)

	db, err := OpenSQLiteReadOnly(path)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	res, err := Verify(context.Background(), db, Options{})
	require.NoError(t, err)
	assert.Equal(t, VerdictValid, res.Verdict)
	assert.Zero(t, res.ChainedEvents)
	assert.Zero(t, res.UnchainedLegacyEvents)
	assert.Nil(t, res.FirstBrokenID)
	assert.False(t, res.RetentionGap.Present)
	assert.False(t, res.Checkpoint.Present)
	assert.NotEmpty(t, res.NotProven, "even a clean empty-DB run must disclose the host-admin caveat")
}

// TestResult_Escalate_NeverDowngrades proves BROKEN always wins over
// INDETERMINATE regardless of call order, and VALID never overwrites either
// — the invariant the whole verdict-computation in verify.go leans on.
func TestResult_Escalate_NeverDowngrades(t *testing.T) {
	r := &Result{Verdict: VerdictValid}
	r.escalate(VerdictIndeterminate, "gap")
	assert.Equal(t, VerdictIndeterminate, r.Verdict)
	assert.Equal(t, "gap", r.Reason)

	r.escalate(VerdictBroken, "tamper")
	assert.Equal(t, VerdictBroken, r.Verdict)
	assert.Equal(t, "tamper", r.Reason)

	// A later, lower-severity call must not overwrite the BROKEN verdict or reason.
	r.escalate(VerdictIndeterminate, "should not apply")
	assert.Equal(t, VerdictBroken, r.Verdict)
	assert.Equal(t, "tamper", r.Reason)
}

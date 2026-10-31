package auditverify

// Tests added for MUTANT-SEC-3: each one pins an effect that a gremlins mutant
// of verify.go, db.go, hash.go, keytransition.go or anchor_bundle.go left
// unchanged. The fixtures are synthetic SQLite files built with this package's
// own hash functions, so these stay inside the no-core/no-storage boundary.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var survivorKey = []byte("0123456789abcdef0123456789abcdef")

// survivorRows builds n correctly chained rows with ids 1..n.
func survivorRows(n int) []*AuditEventRow {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rows := make([]*AuditEventRow, 0, n)
	prev := GenesisHash
	for i := range n {
		e := &AuditEventRow{
			ID:          uint64(i + 1), //nolint:gosec // small test index
			EventType:   "secret.read",
			Description: fmt.Sprintf("event %d", i+1),
			EventTime:   base.Add(time.Duration(i) * time.Second),
			ActorType:   "user",
			PrevHash:    prev,
		}
		e.EntryHash = ComputeEntryHash(e, prev)
		prev = e.EntryHash
		rows = append(rows, e)
	}
	return rows
}

func survivorExec(t *testing.T, path, stmt string, args ...any) {
	t.Helper()
	sqlDB, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer func() { _ = sqlDB.Close() }()
	_, err = sqlDB.Exec(stmt, args...)
	require.NoError(t, err)
}

func survivorInsertRow(t *testing.T, path string, e *AuditEventRow) {
	t.Helper()
	survivorExec(t, path,
		`INSERT INTO audit_events (id, event_type, ip_address, description, event_time, diff, impersonation, actor_type, prev_hash, entry_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		int64(e.ID), e.EventType, e.IPAddress, e.Description, e.EventTime, e.Diff, e.Impersonation, e.ActorType, e.PrevHash, e.EntryHash) //nolint:gosec // small test id
}

func survivorSetMetadata(t *testing.T, path, key, value string) {
	t.Helper()
	survivorExec(t, path, `INSERT INTO system_metadata (key, value) VALUES (?, ?)`, key, value)
}

func survivorInsertCheckpoint(t *testing.T, path string, cp *Checkpoint, token []byte) {
	t.Helper()
	var provider any
	var anchoredAt any
	if len(token) > 0 {
		provider = "test-tsa"
		anchoredAt = time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	}
	survivorExec(t, path,
		`INSERT INTO audit_checkpoints (chained_events, head_id, head_hash, key_version, signature, anchor_token, anchored_at, anchor_provider)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		cp.ChainedEvents, int64(cp.HeadID), cp.HeadHash, cp.KeyVersion, cp.Signature, token, anchoredAt, provider) //nolint:gosec // small test id
}

// survivorDB seeds the schema, inserts rows and opens the file read-only.
func survivorDB(t *testing.T, rows ...*AuditEventRow) (*DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "survivor.db")
	seedEmptySchema(t, path)
	for _, e := range rows {
		survivorInsertRow(t, path, e)
	}
	db, err := OpenSQLiteReadOnly(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}

// survivorCheckpoint signs a checkpoint over the chain's last row.
func survivorCheckpoint(rows []*AuditEventRow, key []byte) *Checkpoint {
	last := rows[len(rows)-1]
	cp := &Checkpoint{ChainedEvents: int64(len(rows)), HeadID: last.ID, HeadHash: last.EntryHash, KeyVersion: "v1"}
	cp.Signature = SignCheckpoint(cp, key)
	return cp
}

func verifyWithKey(t *testing.T, db *DB, opts Options) *Result {
	t.Helper()
	r, err := Verify(context.Background(), db, opts)
	require.NoError(t, err)
	return r
}

// --- db.go ---

func TestRebind_PostgresNumbersEveryPlaceholder(t *testing.T) {
	pg := &DB{backend: BackendPostgres}
	assert.Equal(t, "SELECT a FROM t WHERE x = $1 AND y = $2 LIMIT $3", pg.rebind("SELECT a FROM t WHERE x = ? AND y = ? LIMIT ?"))
	assert.Equal(t, "$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12", pg.rebind("?,?,?,?,?,?,?,?,?,?,?,?"))

	lite := &DB{backend: BackendSQLite}
	assert.Equal(t, "SELECT a FROM t WHERE x = ?", lite.rebind("SELECT a FROM t WHERE x = ?"), "SQLite keeps ? placeholders")
}

func TestNonNegativeUint64_ZeroIsAValidID(t *testing.T) {
	v, err := nonNegativeUint64(sql.NullInt64{Int64: 0, Valid: true}, "user_id")
	require.NoError(t, err)
	require.NotNil(t, v)
	assert.Equal(t, uint64(0), *v)
}

func TestEventRange_ReportsBoundsOfTheTable(t *testing.T) {
	rows := survivorRows(3)
	db, _ := survivorDB(t, rows...)
	fromID, toID, fromTime, toTime, empty, err := db.EventRange(context.Background())
	require.NoError(t, err)
	assert.False(t, empty)
	assert.Equal(t, uint64(1), fromID)
	assert.Equal(t, uint64(3), toID)
	assert.True(t, rows[0].EventTime.Equal(fromTime), "from %v", fromTime)
	assert.True(t, rows[2].EventTime.Equal(toTime), "to %v", toTime)

	emptyDB, _ := survivorDB(t)
	_, _, _, _, empty, err = emptyDB.EventRange(context.Background())
	require.NoError(t, err)
	assert.True(t, empty)
}

func TestEventRange_NegativeIDIsADecodeError(t *testing.T) {
	rows := survivorRows(2)
	rows[0].ID = ^uint64(0) - 3 // stored below as the int64 -4 (see the next line)
	db, path := survivorDB(t)
	survivorExec(t, path,
		`INSERT INTO audit_events (id, event_type, description, event_time, actor_type, prev_hash, entry_hash) VALUES (-4, 'x', 'x', ?, 'user', ?, ?)`,
		rows[1].EventTime, GenesisHash, "h")
	_, _, _, _, _, err := db.EventRange(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "negative")
}

func TestOpenPostgres_UnreachableServerIsAnError(t *testing.T) {
	const dsn = "host=127.0.0.1 port=1 user=nobody dbname=nodb sslmode=disable connect_timeout=2"
	db, err := OpenPostgres(dsn)
	require.Error(t, err)
	assert.Nil(t, db)
	assert.Contains(t, err.Error(), "open postgres")

	cc, perr := pgx.ParseConfig(dsn)
	require.NoError(t, perr)
	db, err = OpenPostgresConfig(cc)
	require.Error(t, err)
	assert.Nil(t, db)
	assert.Contains(t, err.Error(), "open postgres")
}

// --- hash.go ---

func TestEntryHashMatchesAnyKnownEncoding_BothEncodingsAndNeither(t *testing.T) {
	e := survivorRows(1)[0]
	assert.True(t, EntryHashMatchesAnyKnownEncoding(e), "current encoding")

	old := *e
	old.EntryHash = ComputeEntryHashPre1452(&old, old.PrevHash)
	require.NotEqual(t, e.EntryHash, old.EntryHash, "the two encodings must differ for this to prove anything")
	assert.True(t, EntryHashMatchesAnyKnownEncoding(&old), "pre-#1452 encoding")

	bad := *e
	bad.EntryHash = strings.Repeat("ab", 32)
	assert.False(t, EntryHashMatchesAnyKnownEncoding(&bad))
}

// --- keytransition.go ---

func ktRecord(t *testing.T, r KeyTransition) (line string, digest string) {
	t.Helper()
	r.V = 1
	payload, err := json.Marshal(r)
	require.NoError(t, err)
	sum := sha256.Sum256(payload)
	return strings.Join([]string{"akt-v1", base64.RawURLEncoding.EncodeToString(payload), "macold", "macnew"}, "\x1f"), hex.EncodeToString(sum[:])
}

func TestParseKeyTransitions_RecordsMustLinkToTheOneBefore(t *testing.T) {
	first, d1 := ktRecord(t, KeyTransition{Seq: 1, OldKID: "v1", NewKID: "v2"})
	second, d2 := ktRecord(t, KeyTransition{Seq: 2, OldKID: "v2", NewKID: "v3", Prev: d1})
	third, _ := ktRecord(t, KeyTransition{Seq: 3, OldKID: "v3", NewKID: "v4", Prev: d2})

	recs, err := ParseKeyTransitions(strings.Join([]string{first, second, third}, "\n"))
	require.NoError(t, err)
	require.Len(t, recs, 3)
	assert.Equal(t, "v4", recs[2].NewKID)

	reject := func(name string, lines ...string) {
		t.Helper()
		_, err := ParseKeyTransitions(strings.Join(lines, "\n"))
		require.Error(t, err, name)
		assert.ErrorIs(t, err, errKeyTransitionMalformed, name)
	}

	firstWithPrev, _ := ktRecord(t, KeyTransition{Seq: 1, OldKID: "v1", NewKID: "v2", Prev: d1})
	reject("first record claims a predecessor", firstWithPrev)

	wrongSeq, _ := ktRecord(t, KeyTransition{Seq: 3, OldKID: "v2", NewKID: "v3", Prev: d1})
	reject("sequence gap", first, wrongSeq)
	repeatedSeq, _ := ktRecord(t, KeyTransition{Seq: 1, OldKID: "v2", NewKID: "v3", Prev: d1})
	reject("repeated sequence", first, repeatedSeq)

	wrongPrev, _ := ktRecord(t, KeyTransition{Seq: 2, OldKID: "v2", NewKID: "v3", Prev: strings.Repeat("0", 64)})
	reject("prev digest does not match", first, wrongPrev)
	noPrev, _ := ktRecord(t, KeyTransition{Seq: 2, OldKID: "v2", NewKID: "v3"})
	reject("later record without prev digest", first, noPrev)

	wrongKID, _ := ktRecord(t, KeyTransition{Seq: 2, OldKID: "vX", NewKID: "v3", Prev: d1})
	reject("old key version is not the previous new key version", first, wrongKID)

	thirdOnWrongBase, _ := ktRecord(t, KeyTransition{Seq: 3, OldKID: "v3", NewKID: "v4", Prev: d1})
	reject("third record links to the first, not the second", first, second, thirdOnWrongBase)
}

func TestKeyTransitionHeadGone(t *testing.T) {
	rows := survivorRows(3)
	db, _ := survivorDB(t, rows...)
	ctx := context.Background()

	broken := func(r *KeyTransition, res *Result) bool {
		t.Helper()
		gone, err := keyTransitionHeadGone(ctx, db, res, r)
		require.NoError(t, err)
		return gone
	}

	res := &Result{Verdict: VerdictValid}
	assert.False(t, broken(&KeyTransition{Seq: 1}, res), "a record that certified no head has nothing to check")
	assert.Equal(t, VerdictValid, res.Verdict)

	res = &Result{Verdict: VerdictValid}
	assert.False(t, broken(&KeyTransition{Seq: 1, HeadID: 2, HeadHash: rows[1].EntryHash}, res))
	assert.Equal(t, VerdictValid, res.Verdict)

	res = &Result{Verdict: VerdictValid}
	assert.True(t, broken(&KeyTransition{Seq: 1, HeadID: 2, HeadHash: "rewritten"}, res), "head row rewritten")
	assert.Equal(t, VerdictBroken, res.Verdict)
	assert.Contains(t, res.Reason, "missing or was rewritten")

	res = &Result{Verdict: VerdictValid}
	assert.True(t, broken(&KeyTransition{Seq: 1, HeadID: 99, HeadHash: "x"}, res), "head row missing")
	assert.Equal(t, VerdictBroken, res.Verdict)

	// A head removed by an authenticated retention purge is fine, but only a head
	// that sits before the gap.
	purged := func() *Result {
		r := &Result{Verdict: VerdictValid}
		r.RetentionGap = RetentionGapStatus{Present: true, Sanctioned: true, RowID: 50}
		return r
	}
	res = purged()
	assert.False(t, broken(&KeyTransition{Seq: 1, HeadID: 49, HeadHash: "x"}, res))
	assert.Equal(t, VerdictValid, res.Verdict)
	res = purged()
	assert.True(t, broken(&KeyTransition{Seq: 1, HeadID: 50, HeadHash: "x"}, res), "the gap's first row is not purged")
	res = purged()
	assert.True(t, broken(&KeyTransition{Seq: 1, HeadID: 51, HeadHash: "x"}, res))

	res = &Result{Verdict: VerdictValid}
	res.RetentionGap = RetentionGapStatus{Present: true, Sanctioned: false, RowID: 50}
	assert.True(t, broken(&KeyTransition{Seq: 1, HeadID: 49, HeadHash: "x"}, res), "an unsanctioned gap excuses nothing")
}

// --- verify.go ---

func TestResult_Escalate_EqualRankKeepsTheFirstReason(t *testing.T) {
	r := &Result{Verdict: VerdictValid}
	r.escalate(VerdictBroken, "first")
	r.escalate(VerdictBroken, "second")
	assert.Equal(t, "first", r.Reason)

	r = &Result{Verdict: VerdictValid}
	r.escalate(VerdictIndeterminate, "first")
	r.escalate(VerdictIndeterminate, "second")
	assert.Equal(t, "first", r.Reason)
	r.escalate(VerdictBroken, "worse")
	assert.Equal(t, "worse", r.Reason)
	assert.Equal(t, VerdictBroken, r.Verdict)
}

func TestVerify_WalkReadsEveryBatch(t *testing.T) {
	for _, tc := range []struct{ rows, batch int }{{5, 2}, {4, 2}, {3, 3}, {3, 1}, {2, 5}} {
		db, _ := survivorDB(t, survivorRows(tc.rows)...)
		r := verifyWithKey(t, db, Options{BatchSize: tc.batch})
		assert.Equal(t, VerdictValid, r.Verdict, "rows=%d batch=%d: %s", tc.rows, tc.batch, r.Reason)
		assert.Equal(t, int64(tc.rows), r.ChainedEvents, "rows=%d batch=%d", tc.rows, tc.batch)
	}

	// A break in the last batch must still be found.
	rows := survivorRows(5)
	rows[4].PrevHash = strings.Repeat("0", 63) + "1"
	db, _ := survivorDB(t, rows...)
	r := verifyWithKey(t, db, Options{BatchSize: 2})
	assert.Equal(t, VerdictBroken, r.Verdict)
	require.NotNil(t, r.FirstBrokenID)
	assert.Equal(t, uint64(5), *r.FirstBrokenID)
}

func TestVerify_LegacyRowsBeforeTheChainAreCountedNotChained(t *testing.T) {
	legacy := []*AuditEventRow{
		{ID: 1, EventType: "secret.read", Description: "legacy 1", EventTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), ActorType: "user"},
		{ID: 2, EventType: "secret.read", Description: "legacy 2", EventTime: time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC), ActorType: "user"},
	}
	chained := survivorRows(2)
	chained[0].ID, chained[1].ID = 3, 4
	db, _ := survivorDB(t, append(legacy, chained...)...)
	r := verifyWithKey(t, db, Options{})
	assert.Equal(t, VerdictValid, r.Verdict, r.Reason)
	assert.Equal(t, int64(2), r.UnchainedLegacyEvents)
	assert.Equal(t, int64(2), r.ChainedEvents)

	// A row without an entry_hash AFTER the chain began is a removal, not legacy.
	rows := survivorRows(3)
	rows[1].EntryHash = ""
	db, _ = survivorDB(t, rows...)
	r = verifyWithKey(t, db, Options{})
	assert.Equal(t, VerdictBroken, r.Verdict)
	assert.Contains(t, r.Reason, "has no entry_hash")
	require.NotNil(t, r.FirstBrokenID)
	assert.Equal(t, uint64(2), *r.FirstBrokenID)
	assert.Equal(t, int64(1), r.ChainedEvents)
}

func TestVerify_HashMismatchReasonNamesTheEncoding(t *testing.T) {
	// Valid under the pre-#1452 encoding only: an un-migrated upgrade.
	rows := survivorRows(1)
	rows[0].EntryHash = ComputeEntryHashPre1452(rows[0], rows[0].PrevHash)
	db, _ := survivorDB(t, rows...)
	r := verifyWithKey(t, db, Options{})
	assert.Equal(t, VerdictBroken, r.Verdict)
	assert.Contains(t, r.Reason, "valid under the pre-#1452 audit-hash encoding")
	assert.NotContains(t, r.Reason, "matches neither")

	// Valid under neither: the contents changed after the row was written.
	rows = survivorRows(1)
	rows[0].EntryHash = strings.Repeat("cd", 32)
	db, _ = survivorDB(t, rows...)
	r = verifyWithKey(t, db, Options{})
	assert.Equal(t, VerdictBroken, r.Verdict)
	assert.Contains(t, r.Reason, "matches neither the current encoding nor the pre-#1452 one")
	assert.NotContains(t, r.Reason, "valid under the pre-#1452")
}

func TestVerify_BrokenWalkStillReportsTheCheckpoint(t *testing.T) {
	rows := survivorRows(3)
	cp := survivorCheckpoint(rows, survivorKey)
	rows[1].Description = "tampered after the hash was computed"
	db, path := survivorDB(t, rows...)
	survivorInsertCheckpoint(t, path, cp, nil)
	r := verifyWithKey(t, db, Options{CheckpointKey: survivorKey})
	assert.Equal(t, VerdictBroken, r.Verdict)
	assert.True(t, r.Checkpoint.Present)
	assert.Equal(t, "v1", r.Checkpoint.KeyVersion)
	assert.Equal(t, int64(3), r.Checkpoint.ChainedEventsCertified)
	assert.False(t, r.Checkpoint.Authenticated, "the checkpoint is informational once the walk already failed")
}

// A retention anchor "signed" with the empty key must never authenticate a gap
// when the caller supplied no key.
func TestVerify_NoKeyNeverAuthenticatesARetentionAnchor(t *testing.T) {
	skipUnderFIPS140Only(t, "the fixture signs with a 1-byte or nil HMAC key, under crypto/hmac's 112-bit minimum; production keys are 32-byte KEK-derived keys")
	rows := survivorRows(4)
	remaining := rows[1:] // ids 2..4: row 2's prev_hash is no longer the genesis
	db, path := survivorDB(t, remaining...)
	head := remaining[0]
	sig := SignRetentionAnchorV2(head.ID, head.PrevHash, head.EntryHash, 7, "v1", nil)
	survivorSetMetadata(t, path, auditRetentionAnchorKey,
		strings.Join([]string{"v2", "2", head.PrevHash, head.EntryHash, "7", "v1", sig}, "\x1f"))

	r := verifyWithKey(t, db, Options{})
	assert.Equal(t, VerdictIndeterminate, r.Verdict, r.Reason)
	assert.True(t, r.RetentionGap.Present)
	assert.False(t, r.RetentionGap.Authenticated)
	assert.False(t, r.RetentionGap.Sanctioned)
	assert.Zero(t, r.PurgedEvents, "an unauthenticated purge count is never credited")
}

func TestVerify_HighWaterAndCheckpointHeadEnforcement(t *testing.T) {
	rows := survivorRows(3)
	cp := survivorCheckpoint(rows, survivorKey)
	hw := EncodeHighWater(cp, SignCheckpoint(cp, survivorKey))

	t.Run("high-water mark missing although a signed checkpoint exists", func(t *testing.T) {
		db, path := survivorDB(t, rows...)
		survivorInsertCheckpoint(t, path, cp, nil)
		r := verifyWithKey(t, db, Options{CheckpointKey: survivorKey})
		assert.Equal(t, VerdictBroken, r.Verdict)
		assert.Contains(t, r.Reason, "missing or malformed")
	})

	t.Run("clean chain with checkpoint and high-water mark is valid", func(t *testing.T) {
		db, path := survivorDB(t, rows...)
		survivorInsertCheckpoint(t, path, cp, nil)
		survivorSetMetadata(t, path, auditHighWaterKey, hw)
		r := verifyWithKey(t, db, Options{CheckpointKey: survivorKey})
		assert.Equal(t, VerdictValid, r.Verdict, r.Reason)
		assert.True(t, r.Checkpoint.Authenticated)
	})

	t.Run("forged high-water mark names its signature, not its absence", func(t *testing.T) {
		db, path := survivorDB(t, rows...)
		survivorInsertCheckpoint(t, path, cp, nil)
		survivorSetMetadata(t, path, auditHighWaterKey, EncodeHighWater(cp, strings.Repeat("0", 64)))
		r := verifyWithKey(t, db, Options{CheckpointKey: survivorKey})
		assert.Equal(t, VerdictBroken, r.Verdict)
		assert.Contains(t, r.Reason, "high-water mark fails its signature")
	})

	t.Run("certified head row missing", func(t *testing.T) {
		missing := *cp
		missing.HeadID = 99
		missing.Signature = SignCheckpoint(&missing, survivorKey)
		db, path := survivorDB(t, rows...)
		survivorInsertCheckpoint(t, path, &missing, nil)
		survivorSetMetadata(t, path, auditHighWaterKey, EncodeHighWater(&missing, SignCheckpoint(&missing, survivorKey)))
		r := verifyWithKey(t, db, Options{CheckpointKey: survivorKey})
		assert.Equal(t, VerdictBroken, r.Verdict)
		assert.Contains(t, r.Reason, "is missing (tail-truncation or genesis re-seed)")
	})

	t.Run("certified head row rewritten", func(t *testing.T) {
		rewritten := *cp
		rewritten.HeadID = 2
		rewritten.HeadHash = strings.Repeat("ef", 32)
		rewritten.Signature = SignCheckpoint(&rewritten, survivorKey)
		db, path := survivorDB(t, rows...)
		survivorInsertCheckpoint(t, path, &rewritten, nil)
		survivorSetMetadata(t, path, auditHighWaterKey, EncodeHighWater(&rewritten, SignCheckpoint(&rewritten, survivorKey)))
		r := verifyWithKey(t, db, Options{CheckpointKey: survivorKey})
		assert.Equal(t, VerdictBroken, r.Verdict)
		assert.Contains(t, r.Reason, "hash differs from signed checkpoint")
	})
}

// A checkpoint anchor token that does not verify against the configured trust
// root is tamper evidence, not a silent skip.
func TestVerify_CheckpointAnchorTokenMustVerifyAgainstTSARoots(t *testing.T) {
	rows := survivorRows(3)
	cp := survivorCheckpoint(rows, survivorKey)
	hw := EncodeHighWater(cp, SignCheckpoint(cp, survivorKey))
	build := func(t *testing.T) *DB {
		db, path := survivorDB(t, rows...)
		survivorInsertCheckpoint(t, path, cp, []byte("not a timestamp token"))
		survivorSetMetadata(t, path, auditHighWaterKey, hw)
		return db
	}

	r := verifyWithKey(t, build(t), Options{CheckpointKey: survivorKey, TSARoots: x509.NewCertPool()})
	assert.Equal(t, VerdictBroken, r.Verdict)
	assert.Contains(t, r.Reason, "external anchor failed verification")
	assert.True(t, r.Anchor.Present)
	assert.False(t, r.Anchor.Verified)

	// Without roots the token is reported but not judged.
	r = verifyWithKey(t, build(t), Options{CheckpointKey: survivorKey})
	assert.Equal(t, VerdictValid, r.Verdict, r.Reason)
	assert.True(t, r.Anchor.Present)
	assert.False(t, r.Anchor.Verified)
	assert.Contains(t, strings.Join(r.NotProven, "\n"), "no --tsa-roots trust anchor was supplied")
}

func TestVerify_ExternalAnchorAuthentication(t *testing.T) {
	skipUnderFIPS140Only(t, "the fixture signs with a 1-byte or nil HMAC key, under crypto/hmac's 112-bit minimum; production keys are 32-byte KEK-derived keys")
	rows := survivorRows(3)
	bundle := func(key []byte, token []byte) *ExternalAnchorBundle {
		cp := survivorCheckpoint(rows, key)
		return &ExternalAnchorBundle{
			ChainedEvents: cp.ChainedEvents, HeadID: cp.HeadID, HeadHash: cp.HeadHash, KeyVersion: cp.KeyVersion,
			Signature: cp.Signature, AnchorToken: token,
		}
	}
	run := func(t *testing.T, opts Options) *Result {
		db, _ := survivorDB(t, rows...)
		return verifyWithKey(t, db, opts)
	}

	t.Run("signed with the empty key never authenticates a keyless run", func(t *testing.T) {
		r := run(t, Options{ExternalAnchor: bundle(nil, nil)})
		assert.True(t, r.ExternalAnchor.Supplied)
		assert.False(t, r.ExternalAnchor.Authenticated)
	})

	t.Run("key-authenticated bundle without a token needs no trust roots", func(t *testing.T) {
		r := run(t, Options{CheckpointKey: survivorKey, ExternalAnchor: bundle(survivorKey, nil), TSARoots: x509.NewCertPool()})
		assert.True(t, r.ExternalAnchor.Authenticated)
		assert.NotEqual(t, VerdictBroken, r.Verdict, r.Reason)
	})

	t.Run("a token is not judged when no trust roots were supplied", func(t *testing.T) {
		r := run(t, Options{CheckpointKey: survivorKey, ExternalAnchor: bundle(survivorKey, []byte("junk"))})
		assert.True(t, r.ExternalAnchor.Authenticated)
		assert.NotEqual(t, VerdictBroken, r.Verdict, r.Reason)
	})

	t.Run("a token that fails against the trust roots is BROKEN", func(t *testing.T) {
		r := run(t, Options{CheckpointKey: survivorKey, ExternalAnchor: bundle(survivorKey, []byte("junk")), TSARoots: x509.NewCertPool()})
		assert.Equal(t, VerdictBroken, r.Verdict)
		assert.Contains(t, r.Reason, "RFC 3161 token failed verification")
	})

	t.Run("a failing token is BROKEN even when the key does not authenticate the bundle", func(t *testing.T) {
		r := run(t, Options{ExternalAnchor: bundle(survivorKey, []byte("junk")), TSARoots: x509.NewCertPool()})
		assert.Equal(t, VerdictBroken, r.Verdict)
	})
}

func TestDescribeCount(t *testing.T) {
	assert.Equal(t, "3 remain", describeCount(3, 0, "remain"))
	assert.Equal(t, "3 remain plus 2 removed by signed retention purges", describeCount(3, 2, "remain"))
}

func TestBuildNotProven_StatesExactlyWhatWasNotChecked(t *testing.T) {
	joined := func(opts Options, r *Result) string { return strings.Join(buildNotProven(opts, r), "\n") }
	checked := func() *Result { return &Result{OwedBreakGlass: OwedBreakGlassStatus{Checked: true}} }

	assert.Contains(t, joined(Options{}, checked()), "no checkpoint signing key was supplied")
	assert.NotContains(t, joined(Options{CheckpointKey: survivorKey}, checked()), "no checkpoint signing key was supplied")

	r := checked()
	r.Anchor.Present = true
	assert.Contains(t, joined(Options{}, r), "no --tsa-roots trust anchor was supplied")
	assert.Contains(t, joined(Options{TSARoots: x509.NewCertPool()}, r), "did not verify against the supplied trust root")
	assert.NotContains(t, joined(Options{TSARoots: x509.NewCertPool()}, r), "no --tsa-roots")
	r.Anchor.Verified = true
	assert.NotContains(t, joined(Options{}, r), "was not independently re-verified")

	r = checked()
	r.KeyTransition = KeyTransitionStatus{Present: true, Records: 3, OldKeyVerified: 1}
	assert.Contains(t, joined(Options{}, r), "old-key signature of 2 of 3 key transition record(s)")
	r.KeyTransition.OldKeyVerified = 3
	assert.NotContains(t, joined(Options{}, r), "key transition record(s) was not checked")

	r = checked()
	r.ExternalAnchor = ExternalAnchorStatus{Supplied: true}
	assert.Contains(t, joined(Options{}, r), "--anchor bundle was supplied but could not be authenticated")
	r.ExternalAnchor.Authenticated = true
	assert.NotContains(t, joined(Options{}, r), "--anchor bundle was supplied")
}

// --- witness.go ---

func TestWriteWitnessIfHigher_EqualValueIsANoOp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "witness")
	enc := EncodeHighWater(&Checkpoint{ChainedEvents: 5, HeadID: 5, HeadHash: "h", KeyVersion: "v1"}, "sig")
	wrote, err := WriteWitnessIfHigher(path, enc)
	require.NoError(t, err)
	require.True(t, wrote)

	other := EncodeHighWater(&Checkpoint{ChainedEvents: 5, HeadID: 5, HeadHash: "different", KeyVersion: "v1"}, "sig2")
	wrote, err = WriteWitnessIfHigher(path, other)
	require.NoError(t, err)
	assert.False(t, wrote, "an equal mark must not be rewritten")
	cp, _, found, err := ReadWitness(path)
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, "h", cp.HeadHash, "the first mark is still on disk")
}

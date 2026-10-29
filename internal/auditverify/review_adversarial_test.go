package auditverify_test

// REVIEW-AUDITVERIFY-KEYFILES-1: tamper shapes the full-adversarial pass found
// verifying VALID offline. Fixtures are written by the real internal/core
// path; where the server has a rule for the shape, the online verdict is the
// oracle (differential).

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/core"
)

// incrementalFixture is a chain whose checkpoints are written the way the
// server's checkpoint tick writes them, with incremental verification on: a
// signed audit_verification_state row and its in-chain marker exist.
func incrementalFixture(t *testing.T) *diffFixture {
	t.Helper()
	f := newDiffFixture(t)
	f.core.SetAuditIncrementalVerification(time.Minute, 4)
	f.logEvents(10, time.Hour)
	_, _, err := f.core.WriteAuditCheckpointIncremental(f.ctx)
	require.NoError(t, err)
	f.logEvents(3, 0)
	_, _, err = f.core.WriteAuditCheckpointIncremental(f.ctx)
	require.NoError(t, err)
	return f
}

// onlineStatus is a freshly started server's verification status (no
// in-memory state carried over from the writer).
func (f *diffFixture) onlineStatus(key []byte, kid string) *core.AuditVerifyReport {
	f.t.Helper()
	c := core.NewKeyorixCore(f.local)
	c.SetAuditCheckpointKey(key, kid)
	c.SetAuditIncrementalVerification(time.Minute, 4)
	r, err := c.AuditVerificationStatus(f.ctx)
	require.NoError(f.t, err)
	return r
}

func (f *diffFixture) stateValue() string {
	f.t.Helper()
	var v string
	require.NoError(f.t, f.db.Raw(`SELECT value FROM system_metadata WHERE key = 'audit_verification_state'`).Scan(&v).Error)
	require.NotEmpty(f.t, v, "test bug: no verification state row")
	return v
}

// The server's verification state row: online, a deleted, replaced or
// past-the-head row (with the chain still holding its marker) is a sticky
// BROKEN. Offline used to ignore the row, so a DB-only actor who cut the tail
// and erased the checkpoint rows and the high-water mark got VALID from
// verify-audit --checkpoint-key-file while the server reported broken.
func TestReviewAV_VerifyStateRow_OfflineAgreesWithServer(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		tamper     func(f *diffFixture)
		wantBroken bool
		reason     string
	}{
		{name: "untouched", tamper: func(*diffFixture) {}},
		{name: "tail cut, checkpoints, mark and state row erased", wantBroken: true, reason: "state row is missing",
			tamper: func(f *diffFixture) {
				f.exec("DELETE FROM audit_events WHERE id > 12")
				f.eraseLocalCheckpointState()
				f.exec("DELETE FROM system_metadata WHERE key = 'audit_verification_state'")
			}},
		{name: "tail cut, checkpoints and mark erased, state row kept", wantBroken: true, reason: "chain ends at #12",
			tamper: func(f *diffFixture) {
				f.exec("DELETE FROM audit_events WHERE id > 12")
				f.eraseLocalCheckpointState()
			}},
		{name: "state row deleted", wantBroken: true, reason: "state row is missing",
			tamper: func(f *diffFixture) {
				f.exec("DELETE FROM system_metadata WHERE key = 'audit_verification_state'")
			}},
		{name: "state row signature altered", wantBroken: true, reason: "does not verify under the supplied checkpoint key",
			tamper: func(f *diffFixture) {
				v := f.stateValue()
				flip := "0"
				if strings.HasSuffix(v, "0") {
					flip = "1"
				}
				f.exec(`UPDATE system_metadata SET value = ? WHERE key = 'audit_verification_state'`, v[:len(v)-1]+flip)
			}},
		{name: "state row garbled", wantBroken: true, reason: "does not verify under the supplied checkpoint key",
			tamper: func(f *diffFixture) {
				f.exec(`UPDATE system_metadata SET value = 'garbage' WHERE key = 'audit_verification_state'`)
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := incrementalFixture(t)
			tc.tamper(f)
			online := f.onlineStatus(fixedCheckpointKey, "v1")
			require.Equal(t, tc.wantBroken, online.Status == core.AuditVerifyStatusBroken,
				"test bug: the server's verdict is the oracle here (status %s: %s)", online.Status, online.Reason)
			got := f.verifyWith(fixedCheckpointKey)
			if !tc.wantBroken {
				assert.Equal(t, auditverify.VerdictValid, got.Verdict, got.Reason)
				return
			}
			assert.Equal(t, auditverify.VerdictBroken, got.Verdict, got.Reason)
			assert.Contains(t, got.Reason, tc.reason)
		})
	}
}

// A discontinuity the server already recorded in the row stays BROKEN offline
// too, even after the row was re-saved and the chain re-walks cleanly.
func TestReviewAV_VerifyStateRow_RecordedDiscontinuityIsBroken(t *testing.T) {
	t.Parallel()
	f := incrementalFixture(t)
	f.exec("DELETE FROM system_metadata WHERE key = 'audit_verification_state'")
	c := core.NewKeyorixCore(f.local)
	c.SetAuditCheckpointKey(fixedCheckpointKey, "v1")
	c.SetAuditIncrementalVerification(time.Minute, 4)
	_, err := c.RunAuditVerificationTick(f.ctx)
	require.NoError(t, err)
	require.Contains(t, f.stateValue(), "avs-v1", "test bug: the tick did not re-save the row")
	require.Equal(t, core.AuditVerifyStatusBroken, f.onlineStatus(fixedCheckpointKey, "v1").Status)

	got := f.verifyWith(fixedCheckpointKey)
	assert.Equal(t, auditverify.VerdictBroken, got.Verdict, got.Reason)
	assert.Contains(t, got.Reason, "discontinuity")
}

// rotate-kek with incremental verification: VALID offline under the new key,
// and in the crash window after the high-water mark and checkpoint were
// re-signed but before completion saved the state row (old-key row, named by
// the record, no in-chain event yet) not BROKEN either: the server accepts
// that row through the record.
func TestReviewAV_VerifyStateRow_KeyTransitionNotAFalseAlarm(t *testing.T) {
	t.Parallel()
	f := incrementalFixture(t)
	require.NoError(t, f.core.PrepareAuditKeyTransition(f.ctx, ktKey2, "v2"))
	prepared := f.stateValue()
	c2 := core.NewKeyorixCore(f.local)
	c2.SetAuditCheckpointKey(ktKey2, "v2")
	c2.SetAuditIncrementalVerification(time.Minute, 4)
	done, err := c2.CompleteAuditKeyTransition(f.ctx)
	require.NoError(t, err)
	require.True(t, done)

	got := f.verifyWith(ktKey2, fixedCheckpointKey)
	require.Equal(t, auditverify.VerdictValid, got.Verdict, got.Reason)

	// Back to the crash window: the event is the newest row.
	var lastID uint64
	var lastType string
	require.NoError(t, f.db.Raw(`SELECT id, event_type FROM audit_events ORDER BY id DESC LIMIT 1`).Row().Scan(&lastID, &lastType))
	require.Equal(t, "system.audit_key_transition", lastType, "test bug: the transition event is not the newest row")
	f.exec(`DELETE FROM audit_events WHERE id = ?`, lastID)
	f.exec(`UPDATE system_metadata SET value = ? WHERE key = 'audit_verification_state'`, prepared)
	online := f.onlineStatus(ktKey2, "v2")
	require.NotEqual(t, core.AuditVerifyStatusBroken, online.Status, "test bug: the server should accept the carried row: %s", online.Reason)

	got = f.verifyWith(ktKey2)
	assert.NotEqual(t, auditverify.VerdictBroken, got.Verdict, got.Reason)

	// Once the event exists, the old row put back is not accepted.
	f2 := incrementalFixture(t)
	require.NoError(t, f2.core.PrepareAuditKeyTransition(f2.ctx, ktKey2, "v2"))
	prepared = f2.stateValue()
	c3 := core.NewKeyorixCore(f2.local)
	c3.SetAuditCheckpointKey(ktKey2, "v2")
	_, err = c3.CompleteAuditKeyTransition(f2.ctx)
	require.NoError(t, err)
	f2.exec(`UPDATE system_metadata SET value = ? WHERE key = 'audit_verification_state'`, prepared)
	require.Equal(t, core.AuditVerifyStatusBroken, f2.onlineStatus(ktKey2, "v2").Status)
	got = f2.verifyWith(ktKey2)
	assert.Equal(t, auditverify.VerdictBroken, got.Verdict, got.Reason)
}

// Rows the keyset walk (id > last id) never visits: id 0, and with a schema
// edited to drop the primary key, a NULL id or a second row under an id a
// batch ended on. Each used to sit in the table unverified, VALID offline.
func TestReviewAV_RowsOutsideTheWalkAreBroken(t *testing.T) {
	t.Parallel()
	insert := func(f *diffFixture, id any) {
		f.exec(`INSERT INTO audit_events (id, event_type, description, event_time, actor_type, prev_hash, entry_hash, ip_address, diff, impersonation)
			VALUES (?, 'secret.read', 'forged', ?, 'user', 'x', 'y', '', '', false)`, id, time.Now().UTC())
	}
	cases := []struct {
		name      string
		dropPK    bool
		id        any
		batchSize int
	}{
		{name: "id 0", id: 0},
		{name: "NULL id", dropPK: true, id: nil},
		{name: "duplicate id on a batch boundary", dropPK: true, id: 3, batchSize: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newDiffFixture(t)
			f.logEvents(6, time.Hour)
			_, _, err := f.core.WriteAuditCheckpoint(f.ctx)
			require.NoError(t, err)
			if tc.dropPK {
				f.dropAuditEventsPrimaryKey()
			}
			insert(f, tc.id)
			// The whole-table walk catches a duplicate only when both copies
			// land in one batch; the verdict must not depend on that.
			for _, bs := range []int{tc.batchSize, 1, 0} {
				r, err := auditverify.Verify(f.ctx, f.openIndependent(), auditverify.Options{CheckpointKey: fixedCheckpointKey, BatchSize: bs})
				require.NoError(t, err)
				assert.Equal(t, auditverify.VerdictBroken, r.Verdict, "batch size %d: %s", bs, r.Reason)
			}
		})
	}
}

// dropAuditEventsPrimaryKey rebuilds audit_events with the same columns but
// id as a plain integer column, the way a hand-edited SQLite file can.
func (f *diffFixture) dropAuditEventsPrimaryKey() {
	f.t.Helper()
	var ddl string
	require.NoError(f.t, f.db.Raw(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'audit_events'`).Scan(&ddl).Error)
	plain := regexp.MustCompile(`(?i)PRIMARY KEY( AUTOINCREMENT)?`).ReplaceAllString(ddl, "")
	require.NotEqual(f.t, ddl, plain, "test bug: no primary key in %s", ddl)
	f.exec(strings.Replace(plain, "audit_events", "audit_events_plain", 1))
	f.exec(`INSERT INTO audit_events_plain SELECT * FROM audit_events`)
	f.exec(`DROP TABLE audit_events`)
	f.exec(`ALTER TABLE audit_events_plain RENAME TO audit_events`)
}

// An --anchor exported before rotate-kek is signed under the previous key. With
// that key supplied it now authenticates and still catches a truncation that
// also cut away the state marker and erased every local checkpoint artifact.
func TestReviewAV_PreRotationAnchorAuthenticatedByPreviousKey(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(6, time.Hour)
	_, _, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	bundle, err := auditverify.ParseExternalAnchorBundle(captureAnchorBundle(t, f))
	require.NoError(t, err)
	require.NoError(t, f.core.PrepareAuditKeyTransition(f.ctx, ktKey2, "v2"))
	c2 := core.NewKeyorixCore(f.local)
	c2.SetAuditCheckpointKey(ktKey2, "v2")
	_, err = c2.CompleteAuditKeyTransition(f.ctx)
	require.NoError(t, err)

	r := f.verifyWithAnchor(bundle, ktKey2, fixedCheckpointKey)
	require.Equal(t, auditverify.VerdictValid, r.Verdict, r.Reason)
	assert.True(t, r.ExternalAnchor.Authenticated, "the previous key signs the pre-rotation anchor")
	assert.NotContains(t, strings.Join(r.NotProven, "\n"), "could not be authenticated")

	f.exec("DELETE FROM audit_events WHERE id > 3")
	f.eraseLocalCheckpointState()
	f.exec("DELETE FROM system_metadata WHERE key IN ('audit_verification_state', 'audit_key_transitions')")
	r = f.verifyWithAnchor(bundle, ktKey2, fixedCheckpointKey)
	assert.Equal(t, auditverify.VerdictBroken, r.Verdict, r.Reason)
	assert.Contains(t, r.Reason, "externally-held anchor")

	// Without the previous key it stays advisory, and says so.
	r = f.verifyWithAnchor(bundle, ktKey2)
	assert.False(t, r.ExternalAnchor.Authenticated)
	assert.Contains(t, strings.Join(r.NotProven, "\n"), "could not be authenticated")
}

func (f *diffFixture) verifyWithAnchor(b *auditverify.ExternalAnchorBundle, key []byte, prev ...[]byte) *auditverify.Result {
	f.t.Helper()
	r, err := auditverify.Verify(f.ctx, f.openIndependent(), auditverify.Options{CheckpointKey: key, PreviousCheckpointKeys: prev, ExternalAnchor: b})
	require.NoError(f.t, err)
	return r
}

// With a key, a chain with no signed checkpoint (never written, or erased
// together with the mark and the state row) verifies VALID; the report must
// not then claim a DB-only actor could not have cut its tail.
func TestReviewAV_NoCheckpointIsStatedNotProven(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(10, time.Hour)
	_, _, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	assert.NotContains(t, strings.Join(f.verifyWith(fixedCheckpointKey).NotProven, "\n"), "no signed checkpoint")

	f.exec("DELETE FROM audit_events WHERE id > 5")
	f.eraseLocalCheckpointState()
	r := f.verifyWith(fixedCheckpointKey)
	require.Equal(t, auditverify.VerdictValid, r.Verdict, r.Reason)
	assert.Contains(t, strings.Join(r.NotProven, "\n"), "no signed checkpoint was found")
}

// The same over Postgres (the row count is the dialect-rebound query): a row
// with id 0, which a bigserial column accepts when the id is given.
func TestReviewAV_Postgres_IDZeroRowIsBroken(t *testing.T) {
	t.Parallel()
	f := newPGFixture(t)
	f.logEvents(5, time.Hour)
	r, err := auditverify.Verify(f.ctx, f.openIndependent(), auditverify.Options{})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictValid, r.Verdict, r.Reason)

	require.NoError(t, f.db.Exec(`INSERT INTO audit_events (id, event_type, description, event_time, actor_type, prev_hash, entry_hash, ip_address, diff, impersonation)
		VALUES (0, 'secret.read', 'forged', ?, 'user', 'x', 'y', '', '', false)`, time.Now().UTC()).Error)
	r, err = auditverify.Verify(f.ctx, f.openIndependent(), auditverify.Options{})
	require.NoError(t, err)
	assert.Equal(t, auditverify.VerdictBroken, r.Verdict, r.Reason)
	assert.Contains(t, r.Reason, "outside the chain")
}

// An --anchor bundle with head_hash and signature swapped (or any field
// edited) never authenticates, so it can neither clear nor raise a finding;
// the report says it was not cross-checked.
func TestReviewAV_SwappedAnchorBundleNeverAuthenticates(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(6, time.Hour)
	_, _, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	good, err := auditverify.ParseExternalAnchorBundle(captureAnchorBundle(t, f))
	require.NoError(t, err)
	swapped := *good
	swapped.HeadHash, swapped.Signature = good.Signature, good.HeadHash
	inflated := *good
	inflated.ChainedEvents++
	for name, b := range map[string]*auditverify.ExternalAnchorBundle{"swapped": &swapped, "inflated count": &inflated} {
		r := f.verifyWithAnchor(b, fixedCheckpointKey)
		assert.False(t, r.ExternalAnchor.Authenticated, name)
		assert.Equal(t, auditverify.VerdictValid, r.Verdict, "%s: %s", name, r.Reason)
		assert.Contains(t, strings.Join(r.NotProven, "\n"), "could not be authenticated", name)
	}
	assert.True(t, f.verifyWithAnchor(good, fixedCheckpointKey).ExternalAnchor.Authenticated)
}

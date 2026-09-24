package auditverify_test

// External-anchor-bundle differential tests (design §3's `--anchor`): a
// signed checkpoint snapshot supplied out of band, held outside the host's
// blast radius. Builds real checkpoints through the actual server write
// path (like differential_test.go), captures them as a bundle, then proves
// the offline verifier's cross-check catches what an in-DB-only check
// cannot — most importantly, a truncation or genesis re-seed even after the
// LOCAL checkpoint/high-water rows were also deleted.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/auditverify"
)

// captureAnchorBundle reads back the fixture's just-written checkpoint and
// serializes it into the same JSON shape a real `--anchor` file would carry.
func captureAnchorBundle(t *testing.T, f *diffFixture) []byte {
	t.Helper()
	db := f.openIndependent()
	defer db.Close() //nolint:errcheck

	cp, err := db.LatestCheckpoint(f.ctx)
	require.NoError(t, err)
	require.NotNil(t, cp, "test bug: no checkpoint exists to capture")

	b := struct {
		ChainedEvents int64  `json:"chained_events"`
		HeadID        uint64 `json:"head_id"`
		HeadHash      string `json:"head_hash"`
		KeyVersion    string `json:"key_version"`
		Signature     string `json:"signature"`
	}{cp.ChainedEvents, cp.HeadID, cp.HeadHash, cp.KeyVersion, cp.Signature}
	data, err := json.Marshal(b)
	require.NoError(t, err)
	return data
}

// eraseLocalCheckpointState deletes every local trace of checkpointing
// (checkpoint rows + the high-water mark) so a subsequent Verify has
// NOTHING left to compare against on-box — isolating what an externally-held
// anchor alone can still catch.
func (f *diffFixture) eraseLocalCheckpointState() {
	f.exec("DELETE FROM audit_checkpoints")
	f.exec("DELETE FROM system_metadata WHERE key = 'audit_checkpoint_highwater'")
}

func TestDifferential_ExternalAnchor_AuthenticatedChainMatches(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(10, time.Hour)
	_, written, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	require.True(t, written)

	bundleData := captureAnchorBundle(t, f)
	bundle, err := auditverify.ParseExternalAnchorBundle(bundleData)
	require.NoError(t, err)

	db := f.openIndependent()
	got, err := auditverify.Verify(f.ctx, db, auditverify.Options{
		CheckpointKey:  fixedCheckpointKey,
		ExternalAnchor: bundle,
	})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictValid, got.Verdict, "reason: %s", got.Reason)
	require.True(t, got.ExternalAnchor.Supplied)
	require.True(t, got.ExternalAnchor.Authenticated)
}

// TestDifferential_ExternalAnchor_CatchesTruncation_EvenAfterLocalCheckpointErased
// is the whole point of design §3's --anchor: a truncation caught even when
// the database's OWN checkpoint/high-water rows were also deleted, because
// the anchor's ground truth was captured outside this host beforehand.
func TestDifferential_ExternalAnchor_CatchesTruncation_EvenAfterLocalCheckpointErased(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(10, time.Hour)
	_, written, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	require.True(t, written)

	bundleData := captureAnchorBundle(t, f)
	bundle, err := auditverify.ParseExternalAnchorBundle(bundleData)
	require.NoError(t, err)

	// Attacker deletes the tail AND every local trace of the checkpoint/
	// high-water rows — the in-DB-only enforcement path has nothing left to
	// compare against and would report VALID (as
	// TestDifferential_TamperMatrix/truncated_tail already documents for the
	// bare-walk case).
	f.exec("DELETE FROM audit_events WHERE id > 5")
	f.eraseLocalCheckpointState()

	db := f.openIndependent()
	gotWithoutAnchor, err := auditverify.Verify(f.ctx, db, auditverify.Options{CheckpointKey: fixedCheckpointKey})
	require.NoError(t, err)
	require.NotEqual(t, auditverify.VerdictBroken, gotWithoutAnchor.Verdict,
		"test bug: this must reproduce the known in-DB-only blind spot, or the anchor cross-check below proves nothing new")

	gotWithAnchor, err := auditverify.Verify(f.ctx, db, auditverify.Options{
		CheckpointKey:  fixedCheckpointKey,
		ExternalAnchor: bundle,
	})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictBroken, gotWithAnchor.Verdict, "reason: %s", gotWithAnchor.Reason)
	require.Contains(t, gotWithAnchor.Reason, "externally-held anchor")
}

func TestDifferential_ExternalAnchor_UnauthenticatedIsAdvisoryOnly(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(10, time.Hour)
	_, written, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	require.True(t, written)

	bundleData := captureAnchorBundle(t, f)
	bundle, err := auditverify.ParseExternalAnchorBundle(bundleData)
	require.NoError(t, err)

	db := f.openIndependent()
	// No CheckpointKey, no TSARoots: the bundle cannot be authenticated by
	// any method, so it must be advisory-only, never trusted for the
	// chain-length comparison.
	got, err := auditverify.Verify(f.ctx, db, auditverify.Options{ExternalAnchor: bundle})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictValid, got.Verdict, "reason: %s", got.Reason)
	require.True(t, got.ExternalAnchor.Supplied)
	require.False(t, got.ExternalAnchor.Authenticated)

	found := false
	for _, np := range got.NotProven {
		if strings.Contains(np, "anchor bundle was supplied but could not be authenticated") {
			found = true
		}
	}
	require.True(t, found, "expected NotProven to disclose the unauthenticated anchor bundle, got: %v", got.NotProven)
}

// TestDifferential_ExternalAnchor_GenesisReseed simulates ADR-029's other
// documented blind spot for a bare re-walk: not a shorter chain, but a
// wholly different, self-consistent one written from scratch at the same
// ids. A bare re-walk (even with the local checkpoint intact, since it too
// only ever compares against what's currently IN the database) sees this as
// perfectly valid; only an anchor captured BEFORE the re-seed can tell the
// head no longer matches what it certified.
func TestDifferential_ExternalAnchor_GenesisReseed(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(10, time.Hour)
	_, written, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	require.True(t, written)

	bundleData := captureAnchorBundle(t, f)
	bundle, err := auditverify.ParseExternalAnchorBundle(bundleData)
	require.NoError(t, err)

	f.exec("DELETE FROM audit_events")
	f.eraseLocalCheckpointState()

	tr := true
	prevHash := auditverify.GenesisHash
	for i := 1; i <= 10; i++ {
		row := &auditverify.AuditEventRow{
			EventType:   "secret.read",
			IPAddress:   "10.0.0.1",
			Description: fmt.Sprintf("re-seeded event %d", i),
			Success:     &tr,
			EventTime:   time.Now().UTC().Add(time.Duration(i) * time.Second),
			ActorType:   "user",
		}
		entryHash := auditverify.ComputeEntryHash(row, prevHash)
		f.exec(`INSERT INTO audit_events
			(id, event_type, ip_address, description, success, event_time, diff, impersonation, actor_type, prev_hash, entry_hash)
			VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			i, row.EventType, row.IPAddress, row.Description, tr, row.EventTime, row.Diff, false, row.ActorType, prevHash, entryHash)
		prevHash = entryHash
	}

	db := f.openIndependent()
	gotWithoutAnchor, err := auditverify.Verify(f.ctx, db, auditverify.Options{CheckpointKey: fixedCheckpointKey})
	require.NoError(t, err)
	require.NotEqual(t, auditverify.VerdictBroken, gotWithoutAnchor.Verdict,
		"test bug: the re-seeded chain must look clean on its own, or the anchor cross-check below proves nothing new")

	got, err := auditverify.Verify(f.ctx, db, auditverify.Options{
		CheckpointKey:  fixedCheckpointKey,
		ExternalAnchor: bundle,
	})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictBroken, got.Verdict, "reason: %s", got.Reason)
	require.Contains(t, got.Reason, "externally-held anchor")
}

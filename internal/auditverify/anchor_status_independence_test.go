package auditverify_test

// INV-AUDITVERIFY-09: Result.Anchor (the in-DB checkpoint's own RFC 3161
// receipt) and Result.ExternalAnchor (a caller-supplied --anchor bundle held
// outside the host) are independent. Neither one's outcome is written into
// the other, and the verdict reflects the worse of the two: an in-DB anchor
// that looks fine never masks an external anchor that disagrees.
//
// What this does not cover: an in-DB anchor that VERIFIES against a TSA trust
// root. That needs a real RFC 3161 token over the checkpoint, which this
// package's test fixtures cannot mint. The in-DB side here is "present but
// not re-verified" (no TSARoots), the strongest in-DB state reachable without
// one, which is also what a host admin forging the DB can always produce.

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/auditverify"
)

// reseedChain replaces every audit row with a fresh, self-consistent chain of
// n rows at the same ids, as a host admin rewriting history would.
func (f *diffFixture) reseedChain(n int) {
	f.exec("DELETE FROM audit_events")
	tr := true
	prevHash := auditverify.GenesisHash
	for i := 1; i <= n; i++ {
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
}

// TestAnchorStatus_InDBAnchorDoesNotMaskExternalMismatch: a host admin with
// the DB and the checkpoint key re-seeds the chain, signs a fresh in-DB
// checkpoint over it, and attaches an anchor token to that checkpoint. Every
// in-DB check passes. An external bundle captured before the re-seed must
// still drive the verdict to BROKEN, and the in-DB anchor's status must be
// reported as-is, not overwritten by the external one's.
func TestAnchorStatus_InDBAnchorDoesNotMaskExternalMismatch(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(10, time.Hour)
	_, written, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	require.True(t, written)

	bundle, err := auditverify.ParseExternalAnchorBundle(captureAnchorBundle(t, f))
	require.NoError(t, err)

	f.reseedChain(10)
	f.eraseLocalCheckpointState()
	_, written, err = f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	require.True(t, written, "test bug: the forged in-DB checkpoint must be written")
	f.exec("UPDATE audit_checkpoints SET anchor_token = ?, anchor_provider = ?", []byte{0x30, 0x03, 0x02, 0x01, 0x01}, "forged-tsa")

	db := f.openIndependent()

	// Premise: with no external anchor, the forged DB passes, and its in-DB
	// anchor is reported present (not re-verified, since no TSARoots).
	inDBOnly, err := auditverify.Verify(f.ctx, db, auditverify.Options{CheckpointKey: fixedCheckpointKey})
	require.NoError(t, err)
	require.Equal(t, auditverify.VerdictValid, inDBOnly.Verdict,
		"test bug: the forged chain must pass every in-DB check, or the external cross-check below proves nothing; reason: %s", inDBOnly.Reason)
	require.True(t, inDBOnly.Anchor.Present, "test bug: the forged in-DB anchor token must be visible")
	require.False(t, inDBOnly.Anchor.Verified)
	require.False(t, inDBOnly.ExternalAnchor.Supplied, "no --anchor bundle was supplied, so ExternalAnchor must stay empty")
	require.False(t, inDBOnly.ExternalAnchor.Authenticated)

	got, err := auditverify.Verify(f.ctx, db, auditverify.Options{
		CheckpointKey:  fixedCheckpointKey,
		ExternalAnchor: bundle,
	})
	require.NoError(t, err)

	// (a) The two statuses disagree, and each reports only its own anchor.
	require.True(t, got.ExternalAnchor.Supplied)
	require.True(t, got.ExternalAnchor.Authenticated, "the pre-reseed bundle is genuinely signed under the checkpoint key")
	require.Equal(t, inDBOnly.Anchor, got.Anchor,
		"the in-DB anchor's status must be identical with or without an external bundle: the external outcome must never be written into it")

	// (b) The verdict surfaces the external mismatch, not the in-DB pass.
	require.Equal(t, auditverify.VerdictBroken, got.Verdict, "reason: %s", got.Reason)
	require.Contains(t, got.Reason, "externally-held anchor")
	require.Equal(t, 1, got.ExitCode())
}

// TestAnchorStatus_ExternalAuthenticationDoesNotMarkInDBAnchor: the other
// direction. An authenticated external bundle that agrees with the chain must
// not make a missing in-DB anchor look present, or an unverified one look
// verified.
func TestAnchorStatus_ExternalAuthenticationDoesNotMarkInDBAnchor(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		inDBToken   bool
		wantPresent bool
	}{
		{"no in-DB anchor", false, false},
		{"unverified in-DB anchor", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newDiffFixture(t)
			f.logEvents(10, time.Hour)
			_, written, err := f.core.WriteAuditCheckpoint(f.ctx)
			require.NoError(t, err)
			require.True(t, written)
			if tc.inDBToken {
				f.exec("UPDATE audit_checkpoints SET anchor_token = ?, anchor_provider = ?", []byte{0x30, 0x03, 0x02, 0x01, 0x01}, "test-tsa")
			}

			bundle, err := auditverify.ParseExternalAnchorBundle(captureAnchorBundle(t, f))
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

			require.Equal(t, tc.wantPresent, got.Anchor.Present)
			require.False(t, got.Anchor.Verified,
				"an authenticated external bundle must never mark the in-DB anchor verified")
		})
	}
}

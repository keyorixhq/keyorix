package auditverify_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestVerify_SignedCheckpointCountExceedingChainIsBroken pins the count check in
// enforceCheckpoint that nothing else reaches: a checkpoint whose signature is
// valid, whose head id and hash are the chain's real head, and whose
// high-water mark is not above the chain, but which certifies MORE events than
// the chain holds ("audit trail truncated below signed checkpoint").
//
// Every neighbouring check misses this state on purpose: the walk is linked
// and every hash recomputes (no tamper in the rows), the head exists with the
// signed hash (head checks), the row count matches the walk (count guard), and
// the high-water floor is the real count. Only the signed count disagrees. It
// is reachable by a writer-side accounting bug that signs a wrong count, or by
// a holder of the checkpoint key; it is not reachable by editing rows, which
// is why the fuzz and tamper tests never get here (found 2026-11-28 by planting
// "check off" in verify.go: no test in the package failed).
//
// The control re-signs the same checkpoint with the true count and must be
// VALID, so the red case cannot be passing for another reason.
func TestVerify_SignedCheckpointCountExceedingChainIsBroken(t *testing.T) {
	t.Parallel()
	const events = 5

	resign := func(f *diffFixture, count int64) {
		var cp models.AuditCheckpoint
		require.NoError(t, f.db.Order("id DESC").First(&cp).Error)
		sig := auditverify.SignCheckpoint(&auditverify.Checkpoint{
			ChainedEvents: count, HeadID: uint64(cp.HeadID), HeadHash: cp.HeadHash, KeyVersion: cp.KeyVersion,
		}, fixedCheckpointKey)
		f.exec("UPDATE audit_checkpoints SET chained_events = ?, signature = ? WHERE id = ?", count, sig, cp.ID)
	}
	verify := func(f *diffFixture) *auditverify.Result {
		res, err := auditverify.Verify(f.ctx, f.openIndependent(), auditverify.Options{CheckpointKey: fixedCheckpointKey})
		require.NoError(t, err)
		return res
	}
	build := func(t *testing.T) *diffFixture {
		f := newDiffFixture(t)
		f.logEvents(events, time.Hour)
		_, written, err := f.core.WriteAuditCheckpoint(f.ctx)
		require.NoError(t, err)
		require.True(t, written)
		return f
	}

	t.Run("green/control re-signed with the true count", func(t *testing.T) {
		f := build(t)
		resign(f, events)
		res := verify(f)
		require.Equal(t, auditverify.VerdictValid, res.Verdict, "reason: %s", res.Reason)
	})

	t.Run("red/validly signed count above the chain", func(t *testing.T) {
		f := build(t)
		resign(f, events+1)
		res := verify(f)
		require.Equal(t, auditverify.VerdictBroken, res.Verdict, "reason: %s", res.Reason)
		require.Contains(t, res.Reason, "truncated below signed checkpoint")
	})
}

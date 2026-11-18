package core

// AUDIT-GUARDS-TAILS-NOV-1 item 1: accept-loss decides "a lost row, not a
// modified one" from the verifier's typed LinkBroken and the stored rows, not
// by matching the verifier's reason text. Rewording that text must not change
// a verdict, and the old text without the typed signal proves nothing.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// rewordedVerifier rewrites every broken verdict the storage walk returns:
// reason replaces the reason text and linkBroken, when non-nil, overrides
// LinkBroken.
func rewordedVerifier(inner storage.Storage, reason string, linkBroken *bool) storage.Storage {
	edit := func(v *storage.AuditChainVerification) {
		if v == nil || v.Valid {
			return
		}
		if reason != "" {
			v.Reason = reason
		}
		if linkBroken != nil {
			v.LinkBroken = *linkBroken
		}
	}
	return hooked(inner, &storeHooks{
		VerifyAuditChain: func(next storage.Storage, ctx context.Context, a *storage.AuditChainAnchor) (*storage.AuditChainVerification, error) {
			v, err := next.VerifyAuditChain(ctx, a)
			edit(v)
			return v, err
		},
		VerifyAuditChainSegment: func(next storage.Storage, ctx context.Context, seg storage.AuditChainSegment) (*storage.AuditChainVerification, error) {
			v, err := next.VerifyAuditChainSegment(ctx, seg)
			edit(v)
			return v, err
		},
	})
}

// A deleted row with the verifier's reason reworded is still a proven loss.
func TestAuditSeal_LinkBrokenAcceptedWithRewordedReason(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		resume := sealDeleteRow(t, e, e.c, 3)
		e.c.storage = rewordedVerifier(e.c.storage, "row link mismatch (wording changed)", nil)
		sealAccept(t, e.c, sealReq(resume))
		assertSealed(t, e, e.restart(), 1)
	})
}

// The same for a second gap, walked pinned after the first one (the storage
// walk never sets LinkBroken there).
func TestAuditSeal_PinnedGapAcceptedWithRewordedReason(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		first := sealDeleteRow(t, e, e.c, 3)
		require.NoError(t, e.db.Exec("DELETE FROM audit_events WHERE id = 7").Error)
		e.c.storage = rewordedVerifier(e.c.storage, "row link mismatch (wording changed)", nil)
		sealAccept(t, e.c, sealReq(first, 8))
		assertSealed(t, e, e.restart(), 1)
	})
}

// The old reason text without LinkBroken is not a proven loss.
func TestAuditSeal_LinkTextWithoutLinkBrokenRefused(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		resume := sealDeleteRow(t, e, e.c, 3)
		off := false
		e.c.storage = rewordedVerifier(e.c.storage,
			"prev_hash does not link to the preceding event (row inserted, deleted, or reordered)", &off)
		before := sealWriteState(t, e.c)
		sealRefused(t, e.c, sealReq(resume), "modified row, not a lost one")
		require.Equal(t, before, sealWriteState(t, e.c))
	})
}

// A modified row after a sealed gap (walked pinned, so without LinkBroken)
// is refused from the rows, whatever the reason says.
func TestAuditSeal_PinnedModifiedRowRefused(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		first := sealDeleteRow(t, e, e.c, 3)
		tamperDescription(t, e.db, 8)
		e.c.storage = rewordedVerifier(e.c.storage,
			"prev_hash does not link to the preceding event (row inserted, deleted, or reordered)", nil)
		sealRefused(t, e.c, sealReq(first, 8), "modified")
	})
}

// LinkBroken is also set when the earliest row does not match the retention
// re-anchor; that is not a loss accept-loss can prove, under any wording.
func TestAuditSeal_ReanchorMismatchRefusedDespiteLinkBroken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db, fixed := newReanchorTestCore(t)
	for i := range 3 {
		logChainedEvent(t, c, "secret.read", fixed.AddDate(0, 0, -(40+i)))
	}
	survivor := logChainedEvent(t, c, "secret.updated", fixed.AddDate(0, 0, -1))
	for range 4 {
		logChainedEvent(t, c, "secret.updated", fixed.AddDate(0, 0, -1))
	}
	_, err := c.PurgeAuditLogs(ctx, AuditLogRetentionConfig{RetentionDays: 30})
	require.NoError(t, err)
	_, _, err = c.WriteAuditCheckpoint(ctx)
	require.NoError(t, err)
	require.NoError(t, db.Delete(&models.AuditEvent{}, survivor.ID).Error)
	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	require.False(t, v.Valid)
	require.True(t, v.LinkBroken, "precondition: the anchor mismatch carries LinkBroken")
	require.NotNil(t, v.FirstBrokenID)
	c.storage = rewordedVerifier(c.storage, "row link mismatch (wording changed)", nil)
	_, err = c.PlanAuditLossAcceptance(ctx, sealReq(*v.FirstBrokenID))
	require.ErrorIs(t, err, ErrAuditLossRefused)
	require.Contains(t, err.Error(), "does not match the retention re-anchor")
}

// REVFIX-4415-1 (review probe): after two gaps are sealed, the second gap's
// resume row is rewritten so it still recomputes. The pinned walk breaks on
// that row; naming it again is a modified row, refused by planAuditGaps
// itself, not a second gap with the same resume id.
func TestAuditSeal_PinnedSealedResumeRowRewrittenRefused(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		first := sealDeleteRow(t, e, e.c, 3)
		require.NoError(t, e.db.Exec("DELETE FROM audit_events WHERE id = 7").Error)
		sealAccept(t, e.c, sealReq(first, 8))
		rehashFrom(t, e.db, 8, 8)
		c := e.restart()
		before := sealWriteState(t, c)
		sealRefused(t, c, sealReq(8), "is where the gap of seal #1 resumes")
		require.Equal(t, before, sealWriteState(t, c))
	})
}

// The last surviving row before a sealed gap is pinned by the seal too: with
// the row before it deleted and it rewritten (so it still recomputes and its
// link breaks), naming it is a rewritten row, not a new gap.
func TestAuditSeal_PinnedSealedLastGoodRowRewrittenRefused(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		first := sealDeleteRow(t, e, e.c, 3)
		require.NoError(t, e.db.Exec("DELETE FROM audit_events WHERE id = 7").Error)
		sealAccept(t, e.c, sealReq(first, 8))
		require.NoError(t, e.db.Exec("DELETE FROM audit_events WHERE id = 5").Error)
		rehashFrom(t, e.db, 6, 6)
		c := e.restart()
		before := sealWriteState(t, c)
		sealRefused(t, c, sealReq(6), "is the last surviving row before the gap of seal #1")
		require.Equal(t, before, sealWriteState(t, c))
	})
}

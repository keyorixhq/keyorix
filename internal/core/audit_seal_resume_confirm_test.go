// audit_seal_resume_confirm_test.go — #3803: after a completed seal, a writer
// who deletes the seal event and every later row and checkpoint and puts back
// the pre-acceptance high-water mark and verification state makes the next
// accept-loss read as a resume. A resume must not write on --confirm alone.
package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// resumeConfirmSnapshot is every table and row an acceptance writes.
func resumeConfirmSnapshot(t *testing.T, e *fcEnv) []any {
	t.Helper()
	var meta []models.SystemMetadata
	require.NoError(t, e.db.Where("key IN ?", []string{auditSealsKey, auditHighWaterKey, auditVerifyStateKey}).Order("key").Find(&meta).Error)
	var events, checkpoints int64
	require.NoError(t, e.db.Model(&models.AuditEvent{}).Count(&events).Error)
	require.NoError(t, e.db.Model(&models.AuditCheckpoint{}).Count(&checkpoints).Error)
	out := []any{events, checkpoints}
	for _, m := range meta {
		out = append(out, m.Key, m.Value)
	}
	return out
}

// rollBackCompletedSeal accepts the loss of row 3, then undoes everything the
// acceptance wrote after its record, as the issue describes.
func rollBackCompletedSeal(t *testing.T, e *fcEnv) *KeyorixCore {
	t.Helper()
	ctx := context.Background()
	fcCertify(t, e)
	resume := sealDeleteRow(t, e, e.c, 3)
	var head, cp uint
	require.NoError(t, e.db.Raw("SELECT MAX(id) FROM audit_events").Scan(&head).Error)
	require.NoError(t, e.db.Raw("SELECT MAX(id) FROM audit_checkpoints").Scan(&cp).Error)
	var saved []models.SystemMetadata
	require.NoError(t, e.db.Where("key IN ?", []string{auditHighWaterKey, auditVerifyStateKey}).Find(&saved).Error)
	require.Len(t, saved, 2)

	plan, err := e.c.PlanAuditLossAcceptance(ctx, sealReq(resume))
	require.NoError(t, err)
	_, err = e.c.AcceptAuditLoss(ctx, plan)
	require.NoError(t, err)

	require.NoError(t, e.db.Exec("DELETE FROM audit_events WHERE id > ?", head).Error)
	require.NoError(t, e.db.Exec("DELETE FROM audit_checkpoints WHERE id > ?", cp).Error)
	for _, m := range saved {
		require.NoError(t, e.db.Model(&models.SystemMetadata{}).Where("key = ?", m.Key).Update("value", m.Value).Error)
	}
	return e.restart()
}

// The rolled-back database reads as an unfinished acceptance, and the plan is
// made; applying it on --confirm alone (no digest named) writes nothing.
func TestAuditSeal_ResumeWithoutDigestWritesNothing(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		c := rollBackCompletedSeal(t, e)
		plan, err := c.PlanAuditLossAcceptance(ctx, sealReq())
		require.NoError(t, err)
		require.True(t, plan.Resume, "precondition: the rollback reads as an unfinished acceptance")
		before := resumeConfirmSnapshot(t, e)
		_, err = c.AcceptAuditLoss(ctx, plan)
		require.ErrorIs(t, err, ErrAuditLossRefused, "a resume the operator did not name must not write")
		require.Equal(t, before, resumeConfirmSnapshot(t, e), "nothing is written")
		_, err = e.restart().AcceptAuditLoss(ctx, plan)
		require.ErrorIs(t, err, ErrAuditLossRefused)
		require.Equal(t, before, resumeConfirmSnapshot(t, e))
	})
}

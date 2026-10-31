// audit_seal_resume_swap_test.go — REVIEW-3852-DEEP-1 finding 2: a resume
// completes only the unfinished record its --resume-seal digest named. A
// writer who swaps the seal list for another genuine, unfinished record
// between the plan and the apply gets a refusal, and nothing is written.
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// sealCrashAfterRecord writes the seal record of req's acceptance and stops
// before its in-chain event, and returns the stored seal list.
func sealCrashAfterRecord(t *testing.T, e *fcEnv, req AuditLossRequest) string {
	t.Helper()
	ctx := context.Background()
	c := e.restart()
	plan, err := c.PlanAuditLossAcceptance(ctx, req)
	require.NoError(t, err)
	require.False(t, plan.Resume)
	crash := errors.New("crash")
	c.auditSealHook = func(s string) error {
		if s == "record" {
			return crash
		}
		return nil
	}
	_, err = c.AcceptAuditLoss(ctx, plan)
	require.ErrorIs(t, err, crash)
	v, ok, err := c.storage.GetSystemMetadata(ctx, auditSealsKey)
	require.NoError(t, err)
	require.True(t, ok)
	return v
}

func TestAuditSeal_ResumeRefusesSwappedUnfinishedRecord(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		resume := sealDeleteRow(t, e, e.c, 3)

		// Two genuine, unfinished seal #1 records for the same loss.
		named := sealCrashAfterRecord(t, e, sealReq(resume))
		require.NoError(t, e.db.Where("key = ?", auditSealsKey).Delete(&models.SystemMetadata{}).Error)
		other := sealReq(resume)
		other.Reason = "INC-43: a different acceptance"
		swapped := sealCrashAfterRecord(t, e, other)
		require.NotEqual(t, named, swapped)

		require.NoError(t, e.c.storage.SetSystemMetadata(ctx, auditSealsKey, named))
		c := e.restart()
		plan, err := sealResumePlan(t, c, sealReq())
		require.NoError(t, err)
		require.True(t, plan.Resume)
		require.Equal(t, 1, plan.Seq)

		// Between the plan and the apply, the list now holds the other record.
		require.NoError(t, c.storage.SetSystemMetadata(ctx, auditSealsKey, swapped))
		before := resumeConfirmSnapshot(t, e)
		_, err = c.AcceptAuditLoss(ctx, plan)
		require.Error(t, err, "a resume must not complete a record its digest did not name")
		assert.Contains(t, err.Error(), "changed since the plan")
		require.Equal(t, before, resumeConfirmSnapshot(t, e), "nothing is written")

		// The record the digest named is completed by the same plan.
		require.NoError(t, c.storage.SetSystemMetadata(ctx, auditSealsKey, named))
		res, err := c.AcceptAuditLoss(ctx, plan)
		require.NoError(t, err)
		assert.Equal(t, plan.ResumeDigest, res.Digest)
		assertSealed(t, e, e.restart(), 1)
	})
}

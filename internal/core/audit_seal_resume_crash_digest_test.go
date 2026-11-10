// audit_seal_resume_crash_digest_test.go — #3803: the digest a run that stopped
// part way reports is the record the next plan offers to complete, and a wrong
// digest against a rolled-back seal leaves the store untouched.
package core

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditSeal_RecordDigestNamesTheCrashedRecord(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		resume := sealDeleteRow(t, e, e.c, 3)
		plan, err := e.c.PlanAuditLossAcceptance(ctx, sealReq(resume))
		require.NoError(t, err)
		assert.Empty(t, plan.RecordDigest(), "no record is built before the apply")

		e.c.auditSealHook = func(step string) error {
			if step == "record" {
				return errors.New("injected crash")
			}
			return nil
		}
		_, err = e.c.AcceptAuditLoss(ctx, plan)
		require.Error(t, err)
		require.Len(t, plan.RecordDigest(), 64)

		next, err := e.restart().PlanAuditLossAcceptance(ctx, sealReq())
		require.NoError(t, err)
		require.True(t, next.Resume)
		assert.Equal(t, next.ResumeDigest, plan.RecordDigest(), "the crash reports the record the next plan completes")
		assert.Equal(t, next.ResumeDigest, next.RecordDigest())
	})
}

// The #3803 tamper scenario with a digest that names no record: refused, and
// on PostgreSQL too, where no witness would have caught the rollback.
func TestAuditSeal_RolledBackSealWrongDigestWritesNothing(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		c := rollBackCompletedSeal(t, e)
		before := resumeConfirmSnapshot(t, e)
		wrong := sealReq()
		wrong.ResumeSeal = strings.Repeat("ab", 32)
		sealRefused(t, c, wrong, "does not name the unfinished seal #1")
		require.Equal(t, before, resumeConfirmSnapshot(t, e), "nothing is written")
	})
}

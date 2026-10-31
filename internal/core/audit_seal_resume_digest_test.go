// audit_seal_resume_digest_test.go — #3803: a resume completes only with
// --resume-seal naming the digest of the unfinished record the plan printed.
package core

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditSeal_ResumeNeedsRecordDigest(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		c := rollBackCompletedSeal(t, e)
		plan, err := c.PlanAuditLossAcceptance(ctx, sealReq())
		require.NoError(t, err)
		require.True(t, plan.Resume)
		recs, err := parseAuditSeals(sealsValue(t, e.db))
		require.NoError(t, err)
		require.Len(t, recs, 1)
		digest := recs[0].digest()
		assert.Equal(t, digest, plan.ResumeDigest)
		assert.Contains(t, strings.Join(plan.Describe(), "\n"), "requires --resume-seal "+digest)

		wrong := sealReq()
		wrong.ResumeSeal = strings.Repeat("ab", 32)
		sealRefused(t, c, wrong, "does not name the unfinished seal #1")

		named := sealReq()
		named.ResumeSeal = strings.ToUpper(digest)
		plan, err = c.PlanAuditLossAcceptance(ctx, named)
		require.NoError(t, err)
		res, err := c.AcceptAuditLoss(ctx, plan)
		require.NoError(t, err)
		assert.Equal(t, digest, res.Digest)
		assertSealed(t, e, e.restart(), 1)

		// Nothing is unfinished any more: naming a record is refused.
		sealRefused(t, e.restart(), named, "no acceptance is unfinished")
	})
}

// A new acceptance names no record: --resume-seal is refused there too.
func TestAuditSeal_ResumeSealWithoutPendingRefused(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		resume := sealDeleteRow(t, e, e.c, 3)
		req := sealReq(resume)
		req.ResumeSeal = strings.Repeat("cd", 32)
		sealRefused(t, e.c, req, "no acceptance is unfinished")
	})
}

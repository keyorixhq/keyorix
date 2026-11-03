// audit_seal_witness_resume_way_out_test.go — REVIEW-3817-DEEP-1 finding 2: an
// acceptance recorded without counting a higher pre-seal witness (a binary
// from before the witness counted in Before) fails closed at the resume's
// re-seal. A resume cannot change the record, so the refusal names the real
// way out instead of "re-run accept-loss".
package core

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditSeal_ResumeRefusalNamesWitnessWayOut(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		w := filepath.Join(t.TempDir(), ".audit-highwater-witness")
		_, resume, _, witness := witnessRollbackEnv(t, e, w)

		// Planned and recorded by a core that does not read the witness.
		c0 := e.restart()
		plan, err := c0.PlanAuditLossAcceptance(ctx, sealReq(resume))
		require.NoError(t, err)
		crash := errors.New("crash")
		c0.auditSealHook = func(s string) error {
			if s == "record" {
				return crash
			}
			return nil
		}
		_, err = c0.AcceptAuditLoss(ctx, plan)
		require.ErrorIs(t, err, crash)

		c := withWitness(e.restart(), w)
		again, err := sealResumePlan(t, c, sealReq())
		require.NoError(t, err)
		require.True(t, again.Resume)
		_, err = c.AcceptAuditLoss(ctx, again)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "a resume cannot change the record")
		assert.Contains(t, err.Error(), "off-host anchor")
		assert.Contains(t, err.Error(), "move the witness file aside")
		assert.NotContains(t, err.Error(), "so the plan shows it")
		assert.Equal(t, witness, readWitnessFile(t, w), "the witness is not lowered")
	})
}

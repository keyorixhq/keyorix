// audit_seal_unpinned_test.go — #3802: a genuine deletion still seals; the
// surviving rows before the gap that no signed artifact pins are named in the
// plan and recorded in the seal as unauthenticated.
package core

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The row after the oldest checkpoint's head is deleted: that checkpoint pins
// every row before the gap, so nothing is unauthenticated.
func TestAuditSeal_GenuineDeletionPinnedPrefixSeals(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		heads := auditCheckpointHeads(t, e)
		resume := sealDeleteRow(t, e, e.c, heads[0]+1)
		plan, err := e.c.PlanAuditLossAcceptance(ctx, sealReq(resume))
		require.NoError(t, err)
		require.Len(t, plan.Gaps, 1)
		assert.Equal(t, heads[0], plan.Gaps[0].LastGoodID)
		assert.Empty(t, plan.Unpinned, "the oldest checkpoint pins the row before the gap")
		assert.NotContains(t, strings.Join(plan.Describe(), "\n"), "unauthenticated")
		_, err = e.c.AcceptAuditLoss(ctx, plan)
		require.NoError(t, err)
		recs, err := parseAuditSeals(sealsValue(t, e.db))
		require.NoError(t, err)
		require.Len(t, recs, 1)
		assert.Empty(t, recs[0].Unpinned)
		assertSealed(t, e, e.restart(), 1)
	})
}

// Row 3 is deleted, below every checkpoint's head: rows 1-2 are pinned by
// nothing signed. The acceptance goes ahead and says so, in the plan and in
// the record.
func TestAuditSeal_UnpinnedPrefixRecorded(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		require.Greater(t, auditCheckpointHeads(t, e)[0], uint(2), "precondition: no checkpoint pins rows 1-2")
		resume := sealDeleteRow(t, e, e.c, 3)
		plan, err := e.c.PlanAuditLossAcceptance(ctx, sealReq(resume))
		require.NoError(t, err)
		require.Len(t, plan.Unpinned, 1)
		assert.Equal(t, AuditSealSpan{FromID: 1, ThroughID: 2}, plan.Unpinned[0])
		assert.Contains(t, strings.Join(plan.Describe(), "\n"), "unauthenticated: audit events #1 through #2 are pinned by no signed")
		_, err = e.c.AcceptAuditLoss(ctx, plan)
		require.NoError(t, err)
		recs, err := parseAuditSeals(sealsValue(t, e.db))
		require.NoError(t, err)
		require.Len(t, recs, 1)
		assert.Equal(t, plan.Unpinned, recs[0].Unpinned, "the seal records what nothing pinned")
		assertSealed(t, e, e.restart(), 1)
	})
}

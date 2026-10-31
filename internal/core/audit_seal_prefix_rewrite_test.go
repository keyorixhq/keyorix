// audit_seal_prefix_rewrite_test.go — #3802: a database writer who rewrites
// rows before any seal (recomputing their unkeyed hashes) and makes the break
// look like a deletion must not get the rewrite sealed as a loss.
package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// auditCheckpointHeads lists every checkpoint's head id, oldest first.
func auditCheckpointHeads(t *testing.T, e *fcEnv) []uint {
	t.Helper()
	var cps []models.AuditCheckpoint
	require.NoError(t, e.db.Order("id ASC").Find(&cps).Error)
	heads := make([]uint, 0, len(cps))
	for _, cp := range cps {
		heads = append(heads, cp.HeadID)
	}
	return heads
}

// The issue's scenario: rows 1..K rewritten and rehashed, row K+1 deleted, so
// row K+2 breaks like a genuine deletion and the latest checkpoint (past the
// gap) still matches. An older checkpoint pinned a head inside the rewritten
// prefix: the plan must refuse, not seal the forged hash of row K.
func TestAuditSeal_PrefixRewriteBeforeLossRefused(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		heads := auditCheckpointHeads(t, e)
		require.GreaterOrEqual(t, len(heads), 2, "precondition: an older checkpoint and a latest one")
		k := heads[0]
		require.Greater(t, heads[len(heads)-1], k+2, "precondition: the latest checkpoint pins a head past the gap")
		rehashFrom(t, e.db, 1, k)
		resume := sealDeleteRow(t, e, e.c, k+1)
		require.Equal(t, k+2, resume, "precondition: the break reads like a deletion")
		sealRefused(t, e.c, sealReq(resume), "rewritten")
		sealRefused(t, e.restart(), sealReq(resume), "rewritten")
	})
}

// The variant: only row K is rewritten, so the walk breaks at K+1 with no id
// missing (lost == 0 would have read as "unmeasured").
func TestAuditSeal_RewrittenRowNoIDMissingRefused(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		rehashFrom(t, e.db, 4, 4)
		v, err := e.c.VerifyAuditChain(context.Background())
		require.NoError(t, err)
		require.False(t, v.Valid)
		require.NotNil(t, v.FirstBrokenID)
		require.Equal(t, uint(5), *v.FirstBrokenID, "precondition: the break lands on the next id")
		sealRefused(t, e.c, sealReq(5), "no id is missing")
	})
}

// A break over a hole in the ids that is not a loss (ids skipped, as a
// PostgreSQL sequence does on a rolled-back insert): row 6 rewritten, the walk
// breaks at the next id, and the checkpoint, written while every row existed,
// counts every row still there. A measured loss of 0 is a rewrite.
func TestAuditSeal_RewriteOverIDHoleRefused(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		logIncrEvents(t, e.c, e.clk, 10)
		// The hash excludes the id, so moving rows 7.. up keeps the chain.
		require.NoError(t, e.db.Exec("UPDATE audit_events SET id = id + 1000 WHERE id > 6").Error)
		if e.db.Dialector.Name() == "postgres" {
			require.NoError(t, e.db.Exec("SELECT setval(pg_get_serial_sequence('audit_events', 'id'), 5000)").Error)
		}
		c := e.restart()
		v, err := c.VerifyAuditChain(ctx)
		require.NoError(t, err)
		require.True(t, v.Valid, "precondition: an id hole is not a break: %s", v.Reason)
		_, written, err := c.WriteAuditCheckpoint(ctx)
		require.NoError(t, err)
		require.True(t, written)

		rehashFrom(t, e.db, 6, 6)
		v, err = c.VerifyAuditChain(ctx)
		require.NoError(t, err)
		require.False(t, v.Valid)
		require.NotNil(t, v.FirstBrokenID)
		require.Equal(t, uint(1007), *v.FirstBrokenID)
		sealRefused(t, c, sealReq(1007), "counts every row still there")
	})
}

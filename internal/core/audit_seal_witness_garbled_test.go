// audit_seal_witness_garbled_test.go — REVIEW-3817-DEEP-1 finding 1: a host
// witness that claims the current key version but does not authenticate under
// it is garbled or replaced, not "written before a key change". A first
// acceptance refuses it, at the plan and again before the apply writes, as
// the resume path already did.
package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// garbleWitness keeps the witness's fields and key version and replaces its
// signature.
func garbleWitness(t *testing.T, w string) string {
	t.Helper()
	wcp, b, sig, parsed := parseAuditHighWaterSealed(readWitnessFile(t, w))
	require.True(t, parsed)
	bad := strings.Repeat("0", len(sig))
	require.NotEqual(t, sig, bad)
	val := auditHighWaterValueSealed(wcp, b, bad)
	require.NoError(t, os.WriteFile(w, []byte(val), 0o600))
	return val
}

func TestAuditSeal_GarbledCurrentKeyWitnessRefused(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		w := filepath.Join(t.TempDir(), ".audit-highwater-witness")
		withWitness(e.c, w)
		fcCertify(t, e)
		resume := sealDeleteRow(t, e, e.c, 3)
		c := withWitness(e.restart(), w)

		// At the apply: the plan saw an authentic witness, then it is garbled.
		plan, err := c.PlanAuditLossAcceptance(ctx, sealReq(resume))
		require.NoError(t, err)
		val := garbleWitness(t, w)
		_, err = c.AcceptAuditLoss(ctx, plan)
		require.Error(t, err, "the apply must not overwrite a garbled current-key witness")
		assert.Contains(t, err.Error(), "garbled or replaced")
		assert.Equal(t, val, readWitnessFile(t, w), "the witness is not replaced")
		_, found, err := c.storage.GetSystemMetadata(ctx, auditSealsKey)
		require.NoError(t, err)
		assert.False(t, found, "nothing is written: no seal record")

		// At the plan.
		_, err = withWitness(e.restart(), w).PlanAuditLossAcceptance(ctx, sealReq(resume))
		require.ErrorIs(t, err, ErrAuditLossRefused)
		assert.Contains(t, err.Error(), "garbled or replaced")
		assert.NotContains(t, err.Error(), "written before a key change")
	})
}

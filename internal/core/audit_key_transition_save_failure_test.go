// audit_key_transition_save_failure_test.go — a state save that fails while
// PrepareAuditKeyTransition records a broken chain must not leave a failure
// event naming the unsaved generation (MERGE-FIX-3648-2).
//
// #3621 made the checkpoint path append system.audit_chain_verification_failed
// only once the generation it names is stored (TestAuditVerifyStateFailClosed_
// SaveFailureDuringBreak). Prepare, the third caller that records a failure,
// kept the event on a failed save: every later load then read it as a foreign
// failure, a permanent "before a recorded break" discontinuity, and the key
// change itself would carry that false alarm over. The break stays detected:
// the retried prepare walks the same broken chain and records it. Every case
// runs on SQLite and, with KEYORIX_TEST_PG_DSN, PostgreSQL.
package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuditKeyTransition_PrepareSaveFailureDuringBreak(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		before := countEvents(t, e.db, auditChainVerificationFailedEvent)
		tamperDescription(t, e.db, 3)
		unblock := sfBlockStateSave(t, e.db)
		require.Error(t, e.c.PrepareAuditKeyTransition(ctx, aktNewKey, "v2"),
			"prepare walks the broken chain and cannot save the failure")
		assert.Equal(t, before, countEvents(t, e.db, auditChainVerificationFailedEvent),
			"no failure event may name a generation that was never stored")
		unblock()

		c2 := aktRotate(t, e)
		for range 3 {
			fcTick(t, e, c2)
		}
		r := incrVerify(t, c2)
		assert.Equal(t, AuditVerifyStatusBroken, r.Status, "the break is carried over once the save works: %s %s", r.Reason, r.NotProvenReason)
		assert.NotContains(t, r.Reason, fcDiscontinuityText, "a failed save during an honest break must not become a sticky discontinuity")
		assert.NotContains(t, r.Reason, aktTransitionText)
		assert.Equal(t, int64(0), countEvents(t, e.db, fcDiscontinuityEvent), "no discontinuity may be reported")
		assert.Equal(t, before+1, countEvents(t, e.db, auditChainVerificationFailedEvent), "the failure is recorded exactly once, by the save that stored it")
		v, err := c2.VerifyAuditChain(ctx)
		require.NoError(t, err)
		assert.False(t, v.Valid, "a broken chain is never re-notarised under the new key")
	})
}

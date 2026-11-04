// audit_verify_state_cas_test.go — the signed verification state keeps a
// failure one holder of WithAuditCheckpointLock recorded when another holder,
// which loaded the row before it, saves afterwards (AUDIT-HIGHWATER-CAS-1 item
// 2, docs/design/pooler-lock-loss.md row 15). Fixture: hwCASRun
// (audit_highwater_cas_test.go).
package core

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Holder B loaded the state, then holder A recorded a sticky failure, then B
// saved what it had loaded. The failure must survive B's save.
func TestAuditVerifyStateCAS_LostUpdateKeepsRecordedFailure(t *testing.T) {
	t.Parallel()
	hwCASRun(t, func(t *testing.T, p *hwCASPair) {
		ctx := context.Background()
		require.NoError(t, p.a.updateAuditVerifyState(ctx, func(*auditVerifyState) *auditVerifyFailure { return nil }))
		p.b, p.dbB = p.newReplica()

		const reason = "hw-cas: holder A found a broken row"
		reached, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		errB := make(chan error, 1)
		go func() {
			errB <- p.b.updateAuditVerifyState(ctx, func(*auditVerifyState) *auditVerifyFailure {
				once.Do(func() {
					close(reached)
					<-release
				})
				return nil
			})
		}()
		<-reached
		// Holder A: the lock is B's in its own view, A's in the database's (a
		// silent loss), so A runs the section's load-modify-save directly.
		st, _, err := p.a.loadAuditVerifyStateForWrite(ctx)
		require.NoError(t, err)
		failed := recordAuditVerifyFailure(st, p.clk.now(), auditFullSourceJob, nil, reason)
		require.NoError(t, p.a.saveAuditVerifyState(ctx, st))
		p.a.reportAuditVerifyStateEvents(ctx, st, nil, failed)
		close(release)
		require.NoError(t, <-errB)

		got, kind, why := p.a.decodeAuditVerifyState(untrustedMeta(t, p.setup, auditVerifyStateKey))
		require.NotNil(t, got, "the stored state authenticates (%s: %s)", kind, why)
		require.NotNil(t, got.Failure, "holder B's later save of an older state must not drop holder A's failure")
		assert.Equal(t, reason, got.Failure.Reason)
		assert.Greater(t, got.Gen, st.Gen, "holder B saved on top of A's state, not under it")
	})
}

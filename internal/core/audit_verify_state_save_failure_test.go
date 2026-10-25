// audit_verify_state_save_failure_test.go — a state save that fails while a
// tick records an honest break must not leave a failure event naming the
// unsaved generation (AUDIT-VERIFY-STATE-FIX-4, finding M1 of the second #3621
// re-review).
//
// The checkpoint path appended system.audit_chain_verification_failed even when
// saveAuditVerifyState failed. The stored row then had no failure and an audit
// head below that event, so every later load read it as a foreign failure: a
// permanent "before a recorded break" discontinuity whose reason claimed an
// older row was put back, although nothing was. The event is now appended only
// once its generation is stored; the break itself stays detected, because the
// chain is still broken and the next tick records it. Every case runs on SQLite
// and, with KEYORIX_TEST_PG_DSN, PostgreSQL.
package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// sfBlockStateSave makes every write of the verification state row fail (a
// transient DB error) until the returned func is called.
func sfBlockStateSave(t *testing.T, db *gorm.DB) (unblock func()) {
	t.Helper()
	if db.Dialector.Name() == "postgres" {
		require.NoError(t, db.Exec(fmt.Sprintf(`CREATE FUNCTION sf_block_state_save() RETURNS trigger AS $$
			BEGIN IF NEW.key = '%s' THEN RAISE EXCEPTION 'injected save failure'; END IF; RETURN NEW; END
			$$ LANGUAGE plpgsql`, auditVerifyStateKey)).Error)
		require.NoError(t, db.Exec(`CREATE TRIGGER sf_block_state_save BEFORE INSERT OR UPDATE ON system_metadata
			FOR EACH ROW EXECUTE FUNCTION sf_block_state_save()`).Error)
		return func() {
			require.NoError(t, db.Exec(`DROP TRIGGER sf_block_state_save ON system_metadata`).Error)
			require.NoError(t, db.Exec(`DROP FUNCTION sf_block_state_save()`).Error)
		}
	}
	for _, op := range []string{"INSERT", "UPDATE"} {
		require.NoError(t, db.Exec(fmt.Sprintf(`CREATE TRIGGER sf_block_state_save_%[1]s BEFORE %[1]s ON system_metadata
			WHEN NEW.key = '%[2]s' BEGIN SELECT RAISE(ABORT, 'injected save failure'); END`, op, auditVerifyStateKey)).Error)
	}
	return func() {
		for _, op := range []string{"INSERT", "UPDATE"} {
			require.NoError(t, db.Exec(`DROP TRIGGER sf_block_state_save_`+op).Error)
		}
	}
}

func TestAuditVerifyStateFailClosed_SaveFailureDuringBreak(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		before := countEvents(t, e.db, auditChainVerificationFailedEvent)
		unblock := sfBlockStateSave(t, e.db)
		e.clk.advance()
		logIncrEvents(t, e.c, e.clk, 2)
		head := latestEventID(t, e.db)
		tamperDescription(t, e.db, head)
		_, err := e.c.RunAuditVerificationTick(context.Background())
		require.Error(t, err, "the tick detects the break and cannot save it")
		assert.Equal(t, before, countEvents(t, e.db, auditChainVerificationFailedEvent),
			"no failure event may name a generation that was never stored")
		unblock()

		c := e.restart()
		fcTick(t, e, c)
		r := incrVerify(t, c)
		assert.Equal(t, AuditVerifyStatusBroken, r.Status, "the break must still be recorded once the save works: %s %s", r.Reason, r.NotProvenReason)
		assert.NotContains(t, r.Reason, fcDiscontinuityText, "a failed save during an honest break must not become a sticky discontinuity")
		assert.Equal(t, int64(0), countEvents(t, e.db, fcDiscontinuityEvent), "no discontinuity may be reported")
		assert.Equal(t, before+1, countEvents(t, e.db, auditChainVerificationFailedEvent), "the failure is recorded exactly once, by the save that stored it")
		if assert.NotNil(t, r.FirstBrokenID) {
			assert.Equal(t, head, *r.FirstBrokenID)
		}
	})
}

// audit_verify_state_rolling_upgrade_test.go — #3708: during a Helm rolling
// update (RollingUpdate, replicas > 1, ADR-039) a replica from before
// AUDIT-VERIFY-STATE-1 re-signs the state row this binary placed, dropping the
// fields that place it. That row must not latch a sticky discontinuity (no
// command clears one over an intact chain); one full verification re-places it.
// Everything a put-back row could erase still latches: a row from before the
// upgrade, one older than the checkpoint trail, one saved before a recorded
// break, and a discontinuity the older replica dropped
// (audit_verify_state_unplaced_test.go). Every case runs on SQLite and, with
// KEYORIX_TEST_PG_DSN, PostgreSQL.
package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// olderReplicaStateFields are the row fields the state struct had before
// AUDIT-VERIFY-STATE-1 (135f1b37a^:internal/core/audit_verify_state.go); its
// json decode drops every other one.
var olderReplicaStateFields = []string{"v", "gen", "bind", "pin", "rejected", "cycle", "last_full", "last_check", "failure", "job"}

// olderReplicaStateValue is the row an older replica's next save writes over
// val: its load keeps the fields it knows, its save takes the next generation
// (loadAuditVerifyStateForWrite) and binds the current checkpoint trail. No
// second binary is needed: this is that save's exact stored shape.
func olderReplicaStateValue(t *testing.T, c *KeyorixCore, val string, gen uint64) string {
	t.Helper()
	ffDecode(t, c, val)
	parts := strings.Split(val, auditVerifyStateSep)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var all map[string]any
	require.NoError(t, json.Unmarshal(payload, &all))
	m := map[string]any{}
	for _, f := range olderReplicaStateFields {
		if v, ok := all[f]; ok {
			m[f] = v
		}
	}
	bind, err := c.currentAuditVerifyBinding(context.Background())
	require.NoError(t, err)
	m["gen"] = gen
	m["bind"] = map[string]any{"checkpoint_id": bind.CheckpointID, "high_water": bind.HighWater}
	return signedStateValue(t, c, m)
}

// olderReplicaResave stores the older replica's re-sign of the current row and
// returns it.
func olderReplicaResave(t *testing.T, e *fcEnv, c *KeyorixCore) string {
	t.Helper()
	val := fcStateValue(t, e.db)
	v := olderReplicaStateValue(t, c, val, ffDecode(t, c, val).Gen+1)
	fcSetStateValue(t, e.db, v)
	return v
}

// assertNotBroken: neither view reads broken, and no discontinuity was raised.
func assertNotBroken(t *testing.T, e *fcEnv, c *KeyorixCore) *AuditVerifyReport {
	t.Helper()
	r := incrVerify(t, c)
	require.NotEqual(t, AuditVerifyStatusBroken, r.Status, "%s %s", r.Reason, r.NotProvenReason)
	p, err := c.AuditVerificationStatus(context.Background())
	require.NoError(t, err)
	require.NotEqual(t, AuditVerifyStatusBroken, p.Status, "%s %s", p.Reason, p.NotProvenReason)
	require.Zero(t, countEvents(t, e.db, fcDiscontinuityEvent), "no discontinuity is recorded")
	return r
}

// The #3708 red test: the older replica re-signs the placed row (in-process and
// after a restart), then the rollout finishes and one full verification makes
// the status valid again, with the row placed.
func TestAuditVerifyStateRollingUpgrade_OlderReplicaResaveHeals(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		require.Equal(t, int64(1), countEvents(t, e.db, auditVerifyStateMarkerEvent), "precondition: this binary placed the state")

		olderReplicaResave(t, e, e.c)
		r := assertNotBroken(t, e, e.c)
		assert.Equal(t, AuditVerifyStatusNotProven, r.Status)
		assert.Contains(t, r.NotProvenReason, "re-signed by an older server version")
		fcTick(t, e, e.c)
		assertNotBroken(t, e, e.c)

		olderReplicaResave(t, e, e.c)
		c := e.restart()
		assertNotBroken(t, e, c)
		fcTick(t, e, c)
		assertNotBroken(t, e, c)

		// The rollout is over: one full verification re-places the state.
		waitAuditJob(t, c, startFullJobWhenFree(t, c))
		r = assertNotBroken(t, e, c)
		assert.Equal(t, AuditVerifyStatusValid, r.Status, r.NotProvenReason)
		fcTick(t, e, c)
		assert.Equal(t, AuditVerifyStatusValid, assertNotBroken(t, e, c).Status)
		s := ffDecode(t, c, fcStateValue(t, e.db))
		assert.True(t, s.Placed)
		assert.Positive(t, s.AuditHead)
	})
}

// A chain row deleted while the older replica still runs is a real break: the
// full verification reads broken and stays broken.
func TestAuditVerifyStateRollingUpgrade_RealDeletionStillBroken(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		olderReplicaResave(t, e, e.c)
		victim := latestHeadID(t, e.c) - 1
		require.NoError(t, e.db.Where("id = ?", victim).Delete(&models.AuditEvent{}).Error)
		c := e.restart()
		fcTick(t, e, c)
		waitAuditJob(t, c, startFullJobWhenFree(t, c))
		for range 3 {
			fcTick(t, e, c)
			olderReplicaResave(t, e, c)
			c = e.restart()
			assert.Equal(t, AuditVerifyStatusBroken, incrVerify(t, c).Status)
		}
	})
}

// An older replica's row kept by an actor and put back after a break recorded
// later (a failure naming a higher generation) latches.
func TestAuditVerifyStateRollingUpgrade_ResaveBeforeRecordedBreakLatches(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		kept := olderReplicaResave(t, e, e.c)
		recordBreakAndRepair(t, e)
		fcSetStateValue(t, e.db, kept)
		c := e.restart()
		fcTick(t, e, c)
		assertDiscontinuity(t, e, c, "before a recorded break")
		assertDiscontinuitySticky(t, e, c, "before a recorded break")
	})
}

// An older replica's row put back after this binary checkpointed past it (a
// replay) latches.
func TestAuditVerifyStateRollingUpgrade_StaleResaveLatches(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		kept := olderReplicaResave(t, e, e.c)
		c := e.restart()
		for range 2 {
			fcTick(t, e, c)
		}
		fcSetStateValue(t, e.db, kept)
		c2 := e.restart()
		fcTick(t, e, c2)
		assertDiscontinuity(t, e, c2, "before a recorded break")
	})
}

// audit_verify_state_unplaced_test.go — a state row with AuditHead == 0 must not
// skip the before-break checks (AUDIT-VERIFY-STATE-FIX-2, the #3621 blocker).
//
// Two authentic rows carry AuditHead == 0: a row an older binary signed (the
// field did not exist, and an older replica re-signing a newer row drops it),
// and the first row saved on an empty chain. A DB-write actor who kept either
// could put it back after a break and erase the sticky failure or
// discontinuity, because the load could not place such a row against the
// chain. Every case runs on SQLite and, with KEYORIX_TEST_PG_DSN, PostgreSQL.
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

// unplacedFields are the row fields a binary from before AUDIT-VERIFY-STATE-1
// does not know: it drops them when it decodes and re-signs a row.
var unplacedFields = []string{"kid", "audit_head", "placed", "discontinuity"}

// legacyStateValue re-signs the authentic row val as an older binary would: same
// key, same framing, without the fields it does not know.
func legacyStateValue(t *testing.T, c *KeyorixCore, val string) string {
	t.Helper()
	s, kind, why := c.decodeAuditVerifyState(val)
	require.NotNil(t, s, "precondition: the row authenticates (%s: %s)", kind, why)
	parts := strings.Split(val, auditVerifyStateSep)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(payload, &m))
	for _, f := range unplacedFields {
		delete(m, f)
	}
	return signedStateValue(t, c, m)
}

func signedStateValue(t *testing.T, c *KeyorixCore, m map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(m)
	require.NoError(t, err)
	return strings.Join([]string{"avs-v1", base64.RawURLEncoding.EncodeToString(payload), c.signAuditVerifyState(payload)}, auditVerifyStateSep)
}

// recordBreakAndRepair tampers with the newest row, lets a tick record the
// failure, then repairs the row (the actor hides the evidence in the chain).
func recordBreakAndRepair(t *testing.T, e *fcEnv) {
	t.Helper()
	e.clk.advance()
	logIncrEvents(t, e.c, e.clk, 2)
	head := latestEventID(t, e.db)
	tamperDescription(t, e.db, head)
	_, err := e.c.RunAuditVerificationTick(context.Background())
	require.ErrorIs(t, err, ErrAuditCheckpointRefused)
	require.Equal(t, AuditVerifyStatusBroken, incrVerify(t, e.c).Status, "precondition: the break is recorded")
	require.Positive(t, countEvents(t, e.db, "system.audit_chain_verification_failed"))
	require.NoError(t, e.db.Model(&models.AuditEvent{}).Where("id = ?", head).Update("description", "reanchor test event").Error)
}

// (6) The pre-break row, in the form an older binary signed it (no AuditHead),
// put back after the break.
func TestAuditVerifyStateFailClosed_LegacyRowBeforeKnownBreak(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		before := legacyStateValue(t, e.c, fcStateValue(t, e.db))
		recordBreakAndRepair(t, e)
		fcSetStateValue(t, e.db, before)
		c := e.restart()
		fcTick(t, e, c)
		assertDiscontinuity(t, e, c, "before a recorded break")
		assertDiscontinuitySticky(t, e, c, "before a recorded break")
	})
}

// (7) An older replica (rolling upgrade) decodes the row that carries a
// discontinuity and re-signs it without the field. That erases the alarm
// unless the load still sees the in-chain record.
func TestAuditVerifyStateFailClosed_OlderReplicaDropsDiscontinuity(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		fcDeleteState(t, e.db)
		c := e.restart()
		fcTick(t, e, c)
		assertDiscontinuity(t, e, c, "deleted")
		fcSetStateValue(t, e.db, legacyStateValue(t, c, fcStateValue(t, e.db)))
		c2 := e.restart()
		fcTick(t, e, c2)
		assertDiscontinuity(t, e, c2, fcDiscontinuityText)
		assertDiscontinuitySticky(t, e, c2, fcDiscontinuityText)
	})
}

// (8) The first row saved on an empty chain legitimately has AuditHead 0. Kept
// by the actor and put back after a break, it must not erase the break either.
func TestAuditVerifyStateFailClosed_EmptyChainRowBeforeKnownBreak(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		tickOK(t, e.c)
		first := fcStateValue(t, e.db)
		s, _, why := e.c.decodeAuditVerifyState(first)
		require.NotNil(t, s, why)
		require.Zero(t, s.AuditHead, "precondition: the first row was saved on an empty chain")
		for range 8 {
			if incrVerify(t, e.c).Status == AuditVerifyStatusValid {
				break
			}
			fcTick(t, e, e.c)
		}
		require.Equal(t, AuditVerifyStatusValid, incrVerify(t, e.c).Status, "precondition: certified")
		recordBreakAndRepair(t, e)
		fcSetStateValue(t, e.db, first)
		c := e.restart()
		fcTick(t, e, c)
		assertDiscontinuity(t, e, c, "before a recorded break")
		assertDiscontinuitySticky(t, e, c, "before a recorded break")
	})
}

// The honest upgrade still works: a deployment whose only row an older binary
// signed (no marker, no discontinuity in the chain) continues from it, reaches
// valid with no discontinuity, and its next row is placed.
func TestAuditVerifyStateFailClosed_HonestUpgradeFromLegacyRow(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		logIncrEvents(t, e.c, e.clk, 5)
		bind, err := e.c.currentAuditVerifyBinding(context.Background())
		require.NoError(t, err)
		require.NoError(t, e.c.storage.SetSystemMetadata(context.Background(), auditVerifyStateKey, signedStateValue(t, e.c, map[string]any{
			"v": 1, "gen": 4, "bind": map[string]any{"checkpoint_id": bind.CheckpointID, "high_water": bind.HighWater},
		})))
		c := e.restart()
		var r *AuditVerifyReport
		for range 8 {
			fcTick(t, e, c)
			r = incrVerify(t, c)
			require.NotEqual(t, AuditVerifyStatusBroken, r.Status, r.Reason)
			if r.Status == AuditVerifyStatusValid {
				break
			}
		}
		assert.Equal(t, AuditVerifyStatusValid, r.Status, r.NotProvenReason)
		assert.Zero(t, countEvents(t, e.db, fcDiscontinuityEvent))
		s, _, why := c.decodeAuditVerifyState(fcStateValue(t, e.db))
		require.NotNil(t, s, why)
		assert.Greater(t, s.Gen, uint64(4), "the upgraded server continued the generation")
		assert.True(t, s.Placed, "rows this binary saves are placed against the chain")
		assert.Positive(t, s.AuditHead)
	})
}

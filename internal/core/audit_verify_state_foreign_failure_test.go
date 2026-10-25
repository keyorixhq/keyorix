// audit_verify_state_foreign_failure_test.go — a state row put back over a
// recorded break must be a discontinuity whatever failure the row carries
// (AUDIT-VERIFY-STATE-FIX-3, finding H1 of the #3621 re-review).
//
// The before-break check only asked whether the row carried a failure. A row
// with any older, since-cleared failure passed it, so a DB-write actor who kept
// such a row could put it back after a newer break, and the next full
// verification cleared the old failure and read valid: the newer failure and
// the rollback were erased. The load now tolerates, above the row's audit head,
// only the row's own failure event (it names the generation that recorded it)
// and treats every other failure event as a break the row never saw. Every case
// runs on SQLite and, with KEYORIX_TEST_PG_DSN, PostgreSQL.
package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ffBreak tampers with the newest row and lets a tick record the failure.
// It returns the tampered row's id.
func ffBreak(t *testing.T, e *fcEnv, c *KeyorixCore) uint {
	t.Helper()
	e.clk.advance()
	logIncrEvents(t, c, e.clk, 2)
	head := latestEventID(t, e.db)
	tamperDescription(t, e.db, head)
	_, err := c.RunAuditVerificationTick(context.Background())
	require.ErrorIs(t, err, ErrAuditCheckpointRefused)
	require.Equal(t, AuditVerifyStatusBroken, incrVerify(t, c).Status, "precondition: the break is recorded")
	return head
}

// ffRecordingRow tampers with the newest row and records the failure through
// the one save that records it (a tick saves again once the event landed). It
// returns the tampered row's id and that recording row, whose own failure event
// lies above its audit head.
func ffRecordingRow(t *testing.T, e *fcEnv, c *KeyorixCore) (uint, string) {
	t.Helper()
	e.clk.advance()
	logIncrEvents(t, c, e.clk, 2)
	head := latestEventID(t, e.db)
	tamperDescription(t, e.db, head)
	require.NoError(t, c.updateAuditVerifyState(context.Background(), func(st *auditVerifyState) *auditVerifyFailure {
		return recordAuditVerifyFailure(st, c.now(), "tail", &head, "row tampered")
	}))
	row := fcStateValue(t, e.db)
	s := ffDecode(t, c, row)
	require.NotNil(t, s.Failure)
	require.Less(t, s.AuditHead, ffNewestFailureEvent(t, e.db).ID, "precondition: the recording row predates its own failure event")
	return head, row
}

func ffRepair(t *testing.T, e *fcEnv, id uint) {
	t.Helper()
	require.NoError(t, e.db.Model(&models.AuditEvent{}).Where("id = ?", id).Update("description", "reanchor test event").Error)
}

// ffClear runs a full job and ticks until the status reads valid again (the
// honest way a repaired failure is cleared).
func ffClear(t *testing.T, e *fcEnv, c *KeyorixCore) {
	t.Helper()
	id, started, err := c.StartAuditFullVerification(context.Background())
	require.NoError(t, err)
	require.True(t, started)
	waitAuditJob(t, c, id)
	for range 4 {
		if incrVerify(t, c).Status == AuditVerifyStatusValid {
			break
		}
		fcTick(t, e, c)
	}
	require.Equal(t, AuditVerifyStatusValid, incrVerify(t, c).Status, "precondition: the failure is cleared")
}

func ffDecode(t *testing.T, c *KeyorixCore, val string) *auditVerifyState {
	t.Helper()
	s, kind, why := c.decodeAuditVerifyState(val)
	require.NotNil(t, s, "%s: %s", kind, why)
	return s
}

func ffNewestFailureEvent(t *testing.T, db *gorm.DB) models.AuditEvent {
	t.Helper()
	var ev models.AuditEvent
	require.NoError(t, db.Where("event_type = ?", auditChainVerificationFailedEvent).Order("id DESC").First(&ev).Error)
	return ev
}

// ffPutBackOverNewerFailure records break 2 after the kept row, repairs it,
// puts the kept row back and restarts; the result must be a sticky
// discontinuity, not a status a full verification turns valid.
func ffPutBackOverNewerFailure(t *testing.T, e *fcEnv, kept string) {
	t.Helper()
	h2 := ffBreak(t, e, e.c)
	require.Equal(t, int64(2), countEvents(t, e.db, auditChainVerificationFailedEvent))
	ffRepair(t, e, h2)
	fcSetStateValue(t, e.db, kept)
	c := e.restart()
	fcTick(t, e, c)
	assertDiscontinuity(t, e, c, "before a recorded break")
	assertDiscontinuitySticky(t, e, c, "before a recorded break")
}

// (9) The row that recorded failure F1 (its audit head is below F1's own event)
// is kept, F1 is cleared, F2 is recorded, and the row is put back. Before the
// fix the status read valid after the next full verification.
func TestAuditVerifyStateFailClosed_OlderFailureRowBeforeNewerFailure(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		h1, kept := ffRecordingRow(t, e, e.c)
		fcTick(t, e, e.c)
		require.Equal(t, AuditVerifyStatusBroken, incrVerify(t, e.c).Status, "precondition: F1 is recorded")
		ffRepair(t, e, h1)
		ffClear(t, e, e.c)
		ffPutBackOverNewerFailure(t, e, kept)
	})
}

// (10) The kept row was saved after F1's own event landed, so no failure event
// of its own lies above its audit head: tolerating "one failure event above the
// head" would let exactly this row erase F2.
func TestAuditVerifyStateFailClosed_OlderFailureRowSavedAfterItsEvent(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		h1 := ffBreak(t, e, e.c)
		fcTick(t, e, e.c)
		kept := fcStateValue(t, e.db)
		s := ffDecode(t, e.c, kept)
		require.NotNil(t, s.Failure, "precondition: the kept row carries F1")
		require.GreaterOrEqual(t, s.AuditHead, ffNewestFailureEvent(t, e.db).ID, "precondition: the kept row was saved after F1's own event")
		ffRepair(t, e, h1)
		ffClear(t, e, e.c)
		ffPutBackOverNewerFailure(t, e, kept)
	})
}

// The honest case the tolerance exists for: the server restarts while the
// newest row is still the one that recorded the failure, whose own event lies
// above its audit head. That is the recorded failure, not a discontinuity.
func TestAuditVerifyStateFailClosed_RecordingRowAfterRestart(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		ffRecordingRow(t, e, e.c)
		c := e.restart()
		for range 2 {
			r := incrVerify(t, c)
			assert.Equal(t, AuditVerifyStatusBroken, r.Status)
			assert.NotContains(t, r.Reason, fcDiscontinuityText)
			fcTick(t, e, c)
		}
		assert.Zero(t, countEvents(t, e.db, fcDiscontinuityEvent))
	})
}

// A row whose audit head is exactly a failure event's id was saved with that
// event visible: a row that cleared that failure there is not a discontinuity.
func TestAuditVerifyStateFailClosed_ClearedFailureAtEventHead(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		h1 := ffBreak(t, e, e.c)
		ffRepair(t, e, h1)
		ev := ffNewestFailureEvent(t, e.db)
		require.Equal(t, ev.ID, latestEventID(t, e.db), "precondition: the failure event is the chain head")
		require.NoError(t, e.c.updateAuditVerifyState(context.Background(), func(st *auditVerifyState) *auditVerifyFailure {
			st.Failure = nil // as a passing full verification would
			return nil
		}))
		s := ffDecode(t, e.c, fcStateValue(t, e.db))
		require.Nil(t, s.Failure)
		require.Equal(t, ev.ID, s.AuditHead, "precondition: saved with the failure event as its head")
		c := e.restart()
		r := incrVerify(t, c)
		assert.NotContains(t, r.Reason, fcDiscontinuityText)
		fcTick(t, e, c)
		assert.Zero(t, countEvents(t, e.db, fcDiscontinuityEvent))
	})
}

// After a lost row and a restart, generations must not start over: a failure
// recorded then could reuse an old failure's generation and pass as a kept
// row's own.
func TestAuditVerifyStateFailClosed_GenerationsOutliveLostRow(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		ffBreak(t, e, e.c)
		old := ffDecode(t, e.c, fcStateValue(t, e.db))
		require.NotNil(t, old.Failure)
		fcDeleteState(t, e.db)
		c := e.restart()
		fcTick(t, e, c)
		assertDiscontinuity(t, e, c, "deleted")
		s := ffDecode(t, c, fcStateValue(t, e.db))
		assert.Greater(t, s.Gen, old.Failure.Gen, "a new row's generation stays above every recorded failure's")
	})
}

// The unplaced-row check also holds when only a discontinuity event is left
// (the marker events gone): an older replica's re-sign that dropped the
// discontinuity must not erase it.
func TestAuditVerifyStateFailClosed_UnplacedRowDiscontinuityEventOnly(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		fcDeleteState(t, e.db)
		c := e.restart()
		fcTick(t, e, c)
		assertDiscontinuity(t, e, c, "deleted")
		fcSetStateValue(t, e.db, legacyStateValue(t, c, fcStateValue(t, e.db)))
		require.NoError(t, e.db.Model(&models.AuditEvent{}).Where("event_type = ?", auditVerifyStateMarkerEvent).
			Update("event_type", "secret.read").Error)
		require.Zero(t, countEvents(t, e.db, auditVerifyStateMarkerEvent), "precondition: no marker left")
		c2 := e.restart()
		r := incrVerify(t, c2)
		assert.Equal(t, AuditVerifyStatusBroken, r.Status)
		assert.Contains(t, r.Reason, "carries no audit head")
		fcTick(t, e, c2)
		assertDiscontinuity(t, e, c2, "before a recorded break")
	})
}

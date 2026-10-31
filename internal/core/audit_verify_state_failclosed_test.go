// audit_verify_state_failclosed_test.go — the signed verification state row
// (audit_verify_state.go) must never be silently re-created from whatever is
// found (AUDIT-VERIFY-STATE-1). A DB-write actor without the signing key, or a
// bug, that deletes, garbles, replaces or rolls back the row erases the pin and
// the sticky failure that prove rows were lost. Each such row now raises a
// sticky "verification state discontinuity": the status reads broken with a
// distinct reason, the failure gauge and an in-chain event fire, and no
// verification clears it. An honest first start (no row, nothing that proves a
// row existed) still works.
//
// Every case runs on SQLite and, with KEYORIX_TEST_PG_DSN, on PostgreSQL.
package core

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const (
	fcDiscontinuityEvent = "system.audit_verification_state_discontinuity"
	fcDiscontinuityText  = "verification state discontinuity"
)

// fcEnv is one certified deployment: c is the running process, restart starts
// a new one on the same database and key (in-memory floors empty).
type fcEnv struct {
	c       *KeyorixCore
	db      *gorm.DB
	clk     *incrClock
	restart func() *KeyorixCore
}

type fcBackend struct {
	name string
	env  func(t *testing.T) *fcEnv
}

var fcBackends = []fcBackend{
	{"sqlite", func(t *testing.T) *fcEnv {
		c, db, clk := newIncrementalTestCore(t, 3)
		s := c.storage.(*store.LocalStorage)
		return &fcEnv{c: c, db: db, clk: clk, restart: func() *KeyorixCore { return restartCore(t, s, clk, true) }}
	}},
	{"postgres", func(t *testing.T) *fcEnv {
		c, db, clk, dsn := newLaunderPG(t)
		return &fcEnv{c: c, db: db, clk: clk, restart: func() *KeyorixCore {
			return restartCore(t, store.NewLocalStorage(pgOpen(t, dsn)), clk, true)
		}}
	}},
}

// fcRun runs body once per backend.
func fcRun(t *testing.T, body func(t *testing.T, e *fcEnv)) {
	t.Helper()
	for _, b := range fcBackends {
		t.Run(b.name, func(t *testing.T) {
			t.Parallel()
			body(t, b.env(t))
		})
	}
}

// fcCertify builds a deployment whose incremental status reads valid: two
// checkpoints (10 events) and a completed rolling cycle.
func fcCertify(t *testing.T, e *fcEnv) {
	t.Helper()
	launderCertify(t, e.c, e.clk)
	for range 6 {
		if incrVerify(t, e.c).Status == AuditVerifyStatusValid {
			return
		}
		e.clk.advance()
		logIncrEvents(t, e.c, e.clk, 1)
		tickOK(t, e.c)
	}
	r := incrVerify(t, e.c)
	require.Equal(t, AuditVerifyStatusValid, r.Status, "precondition: certified deployment reads valid: %s", r.NotProvenReason)
}

func fcStateValue(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var row models.SystemMetadata
	require.NoError(t, db.Where(&models.SystemMetadata{Key: auditVerifyStateKey}).First(&row).Error)
	return row.Value
}

func fcSetStateValue(t *testing.T, db *gorm.DB, val string) {
	t.Helper()
	require.NoError(t, db.Model(&models.SystemMetadata{}).Where(&models.SystemMetadata{Key: auditVerifyStateKey}).
		Update("value", val).Error)
}

func fcDeleteState(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.Where(&models.SystemMetadata{Key: auditVerifyStateKey}).Delete(&models.SystemMetadata{}).Error)
}

// fcTick is one scheduler tick after a day of ordinary activity. A refusal is
// fine here (the state may prove a break); any other error is not.
func fcTick(t *testing.T, e *fcEnv, c *KeyorixCore) {
	t.Helper()
	e.clk.advance()
	logIncrEvents(t, c, e.clk, 1)
	if _, err := c.RunAuditVerificationTick(context.Background()); err != nil {
		require.ErrorIs(t, err, ErrAuditCheckpointRefused)
	}
}

// awaitOwnFullJob returns once the full job THIS core started (id, from
// startFullJobWhenFree) has finished and saved its result. It does not poll
// against a wall-clock window: the job walks the whole chain with several
// queries per event, so on Postgres under -race and CPU contention it takes
// longer than waitAuditJob's 10 s while still being healthy (#3715: the intact
// chain of _RowDeleted is walked in full; the truncated chains of the sibling
// cases are not). StartAuditFullVerification takes auditVerifyJobMu for the
// goroutine, which releases it only after the result is saved, so acquiring
// the mutex is the completion signal. A job that never ends is a hang, and the
// go test timeout is the detector for that.
func awaitOwnFullJob(t *testing.T, c *KeyorixCore, id string) *AuditVerifyJobStatus {
	t.Helper()
	c.auditVerifyJobMu.Lock()
	c.auditVerifyJobMu.Unlock() //nolint:staticcheck // SA2001: the empty critical section is the wait
	j, err := c.AuditFullVerificationJob(context.Background(), id)
	require.NoError(t, err)
	require.NotEqual(t, AuditVerifyJobRunning, j.State, "the job goroutine released its mutex, so its result is saved")
	return j
}

// assertDiscontinuity: both status views read broken with the distinct reason
// naming kind, and the in-chain record exists.
func assertDiscontinuity(t *testing.T, e *fcEnv, c *KeyorixCore, kind string) {
	t.Helper()
	r := incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusBroken, r.Status, "status must be broken, got %s: %s %s", r.Status, r.Reason, r.NotProvenReason)
	assert.Contains(t, r.Reason, fcDiscontinuityText)
	assert.Contains(t, r.Reason, kind)
	p, err := c.AuditVerificationStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, AuditVerifyStatusBroken, p.Status, "posture must be broken too: %s", p.NotProvenReason)
	assert.Contains(t, p.Reason, fcDiscontinuityText)
	assert.Positive(t, countEvents(t, e.db, fcDiscontinuityEvent), "the discontinuity is recorded in the chain")
}

// assertDiscontinuitySticky: ticks, a passing full job and a second restart do
// not clear it; nothing but an audited operator action may (not in this PR).
func assertDiscontinuitySticky(t *testing.T, e *fcEnv, c *KeyorixCore, kind string) {
	t.Helper()
	for range 4 {
		fcTick(t, e, c)
	}
	id := startFullJobWhenFree(t, c)
	awaitOwnFullJob(t, c, id)
	assertDiscontinuity(t, e, c, kind)
	c2 := e.restart()
	fcTick(t, e, c2)
	assertDiscontinuity(t, e, c2, kind)
}

// (1) The row is deleted, then the server restarts: nothing in memory remembers
// it, so before this change the next tick started over as on a fresh install.
func TestAuditVerifyStateFailClosed_RowDeleted(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		fcDeleteState(t, e.db)
		c := e.restart()
		fcTick(t, e, c)
		assertDiscontinuity(t, e, c, "deleted")
		assertDiscontinuitySticky(t, e, c, "deleted")
	})
}

// (1b) The residual risk #3547 recorded: truncate the tail, relabel the
// checkpoint and high-water key_version, and delete the state row so its pin
// is gone. The re-baseline must not read as a clean chain.
func TestAuditVerifyStateFailClosed_RowDeletedWithLaunder(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		launderAttack(t, e.db)
		fcDeleteState(t, e.db)
		c := e.restart()
		fcTick(t, e, c)
		assertDiscontinuity(t, e, c, "deleted")
		assertDiscontinuitySticky(t, e, c, "deleted")
	})
}

// (1c) Deleted while the server runs: the in-process generation floor saw it.
func TestAuditVerifyStateFailClosed_RowDeletedMidRun(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		fcDeleteState(t, e.db)
		fcTick(t, e, e.c)
		assertDiscontinuity(t, e, e.c, "deleted")
	})
}

// (2) Garbled: framing intact, payload not decodable; and truncated mid-value.
func TestAuditVerifyStateFailClosed_RowGarbled(t *testing.T) {
	t.Parallel()
	garble := map[string]func(string) string{
		"payload": func(string) string {
			return strings.Join([]string{"avs-v1", "!!not-base64!!", "00"}, auditVerifyStateSep)
		},
		"truncated": func(v string) string { return v[:len(v)/2] },
		"signature": func(v string) string {
			parts := strings.Split(v, auditVerifyStateSep)
			sig := []byte(parts[len(parts)-1])
			sig[0] ^= 1
			parts[len(parts)-1] = string(sig)
			return strings.Join(parts, auditVerifyStateSep)
		},
	}
	for name, mutate := range garble {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fcRun(t, func(t *testing.T, e *fcEnv) {
				fcCertify(t, e)
				fcSetStateValue(t, e.db, mutate(fcStateValue(t, e.db)))
				c := e.restart()
				fcTick(t, e, c)
				assertDiscontinuity(t, e, c, "garbled")
				assertDiscontinuitySticky(t, e, c, "garbled")
			})
		})
	}
}

// (3) A row authentic under another key (another key epoch): its key_version
// claim is not authenticated under the current key, so it is not a basis to
// start over silently. This is also what an unrecorded rotate-kek looks like.
func TestAuditVerifyStateFailClosed_RowFromOtherKeyEpoch(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		other := e.restart()
		other.SetAuditCheckpointKey([]byte("another-key-epoch-32-bytes-long-"), "v9")
		require.NoError(t, other.updateAuditVerifyState(context.Background(), func(*auditVerifyState) *auditVerifyFailure { return nil }))
		c := e.restart()
		fcTick(t, e, c)
		assertDiscontinuity(t, e, c, "key epoch")
		assertDiscontinuitySticky(t, e, c, "key epoch")
	})
}

// (4) An authentic row that claims rows past the chain head: rows it verified
// were removed. The posture reads the state alone, so before this change it
// kept reading valid until the next tick.
func TestAuditVerifyStateFailClosed_RowPastChainHead(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		require.NoError(t, e.db.Exec("DELETE FROM audit_events WHERE id > 6").Error)
		c := e.restart()
		p, err := c.AuditVerificationStatus(context.Background())
		require.NoError(t, err)
		assert.Equal(t, AuditVerifyStatusBroken, p.Status, "posture over a state past the chain head: %s", p.NotProvenReason)
		assert.Contains(t, p.Reason, fcDiscontinuityText)
		assert.Contains(t, p.Reason, "past the chain head")
		fcTick(t, e, c)
		assertDiscontinuity(t, e, c, "past the chain head")
		assertDiscontinuitySticky(t, e, c, "past the chain head")
	})
}

// (5) An authentic older row put back over one that recorded a break: the
// failure is erased and, after a restart, the generation floor is gone too.
// The checkpoint trail did not move (a recorded failure refuses checkpoints),
// so the binding check alone accepts the older row.
func TestAuditVerifyStateFailClosed_RowBeforeKnownBreak(t *testing.T) {
	t.Parallel()
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		before := fcStateValue(t, e.db)
		e.clk.advance()
		logIncrEvents(t, e.c, e.clk, 2)
		head := latestEventID(t, e.db)
		tamperDescription(t, e.db, head)
		_, err := e.c.RunAuditVerificationTick(context.Background())
		require.ErrorIs(t, err, ErrAuditCheckpointRefused)
		require.Equal(t, AuditVerifyStatusBroken, incrVerify(t, e.c).Status, "precondition: the break is recorded")
		require.Positive(t, countEvents(t, e.db, "system.audit_chain_verification_failed"))

		// The actor repairs the row and puts the pre-break state back.
		require.NoError(t, e.db.Model(&models.AuditEvent{}).Where("id = ?", head).Update("description", "reanchor test event").Error)
		fcSetStateValue(t, e.db, before)
		c := e.restart()
		fcTick(t, e, c)
		assertDiscontinuity(t, e, c, "before a recorded break")
		assertDiscontinuitySticky(t, e, c, "before a recorded break")
	})
}

// An honest first start must still work: an empty database, then a chain
// written before any state existed (an upgraded deployment), both reach valid
// with no discontinuity.
func TestAuditVerifyStateFailClosed_HonestFirstStart(t *testing.T) {
	t.Parallel()
	for _, rows := range []int{0, 5} {
		fcRun(t, func(t *testing.T, e *fcEnv) {
			logIncrEvents(t, e.c, e.clk, rows)
			var r *AuditVerifyReport
			for range 8 {
				fcTick(t, e, e.c)
				r = incrVerify(t, e.c)
				require.NotEqual(t, AuditVerifyStatusBroken, r.Status, r.Reason)
				if r.Status == AuditVerifyStatusValid {
					break
				}
			}
			assert.Equal(t, AuditVerifyStatusValid, r.Status, r.NotProvenReason)
			assert.Zero(t, countEvents(t, e.db, fcDiscontinuityEvent))
			// A restart of an honest deployment is not a discontinuity either.
			c := e.restart()
			fcTick(t, e, c)
			assert.Equal(t, AuditVerifyStatusValid, incrVerify(t, c).Status)
			assert.Zero(t, countEvents(t, e.db, fcDiscontinuityEvent))
		})
	}
}

func latestEventID(t *testing.T, db *gorm.DB) uint {
	t.Helper()
	var ev models.AuditEvent
	require.NoError(t, db.Order("id DESC").First(&ev).Error)
	return ev.ID
}

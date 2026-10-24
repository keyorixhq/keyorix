// audit_key_transition_test.go — a key change (rotate-kek, migrate-provider)
// carries the audit verification state over under both keys
// (docs/design-audit-key-transition.md, AUDIT-ROTATE-TRANSITION-1, #3642).
//
// A rotation is simulated the way the commands drive core: the running process
// on the old key prepares the cross-signed record (PrepareAuditKeyTransition),
// a process on the new key completes it (CompleteAuditKeyTransition, run by the
// command after the key files commit and again at every server start).
//
// Every case runs on SQLite and, with KEYORIX_TEST_PG_DSN, on PostgreSQL.
package core

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

var (
	aktNewKey = []byte("rotated-key-32-bytes-long-------")
	aktKey3   = []byte("third-key-32-bytes-long---------")
)

const aktTransitionText = "verification state discontinuity (key transition)"

// aktOnKey starts a process on the same database under key/kid, the way the
// server wires it (SetAuditCheckpointKey, then CompleteAuditKeyTransition when
// complete, then SeedAuditWatermark).
func aktOnKey(t *testing.T, e *fcEnv, key []byte, kid string, complete bool) *KeyorixCore {
	t.Helper()
	c := e.restart()
	c.SetAuditCheckpointKey(key, kid)
	if complete {
		_, err := c.CompleteAuditKeyTransition(context.Background())
		require.NoError(t, err)
	}
	c.SeedAuditWatermark(context.Background())
	return c
}

// aktRotate is a whole honest rotation from the running v1 process to v2.
func aktRotate(t *testing.T, e *fcEnv) *KeyorixCore {
	t.Helper()
	require.NoError(t, e.c.PrepareAuditKeyTransition(context.Background(), aktNewKey, "v2"))
	return aktOnKey(t, e, aktNewKey, "v2", true)
}

// aktSettle runs a few ticks (each after a day of activity) and returns the
// incremental report.
func aktSettle(t *testing.T, e *fcEnv, c *KeyorixCore) *AuditVerifyReport {
	t.Helper()
	for range 6 {
		fcTick(t, e, c)
		if r := incrVerify(t, c); r.Status == AuditVerifyStatusValid {
			return r
		}
	}
	return incrVerify(t, c)
}

func aktAssertValid(t *testing.T, e *fcEnv, c *KeyorixCore) {
	t.Helper()
	r := aktSettle(t, e, c)
	assert.Equal(t, AuditVerifyStatusValid, r.Status, "after an honest key change the status reads valid: %s %s", r.Reason, r.NotProvenReason)
	v, err := c.VerifyAuditChain(context.Background())
	require.NoError(t, err)
	assert.True(t, v.Valid, v.Reason)
	assert.Zero(t, countEvents(t, e.db, fcDiscontinuityEvent), "no discontinuity is recorded for an honest key change")
}

func aktTransitionsValue(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var row models.SystemMetadata
	require.NoError(t, db.Where(&models.SystemMetadata{Key: auditKeyTransitionsKey}).First(&row).Error)
	return row.Value
}

func aktSetTransitionsValue(t *testing.T, db *gorm.DB, val string) {
	t.Helper()
	require.NoError(t, db.Model(&models.SystemMetadata{}).Where(&models.SystemMetadata{Key: auditKeyTransitionsKey}).
		Update("value", val).Error)
}

// (1) The normal path: the state, the latest checkpoint and the high-water
// mark are carried over; the status reads valid straight after the change and
// after another restart, and a fresh checkpoint is signed under the new key.
func TestAuditKeyTransition_RotationCarriesStateOver(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		c2 := aktRotate(t, e)
		cp, err := c2.storage.LatestAuditCheckpoint(ctx)
		require.NoError(t, err)
		require.NotNil(t, cp)
		assert.Equal(t, "v2", cp.KeyVersion, "a fresh checkpoint is written under the new key")
		assert.True(t, c2.checkpointSignatureValid(cp))
		assert.Equal(t, int64(1), countEvents(t, e.db, auditKeyTransitionEvent), "one in-chain transition record")
		aktAssertValid(t, e, c2)
		aktAssertValid(t, e, aktOnKey(t, e, aktNewKey, "v2", true))
	})
}

// (2) RECOVERY-OPTIONS-1 F2: on an install that has had a retention purge,
// the online walk after a key change used to need genesis and read broken.
func TestAuditKeyTransition_PurgedInstallStaysValid(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		// Sixty days later every certified row is past retention.
		e.clk.t = e.clk.t.AddDate(0, 0, 60)
		logIncrEvents(t, e.c, e.clk, 3)
		_, err := e.c.PurgeAuditLogs(ctx, AuditLogRetentionConfig{RetentionDays: 30})
		require.NoError(t, err)
		anchor, err := e.c.loadAuditRetentionAnchor(ctx)
		require.NoError(t, err)
		require.NotNil(t, anchor, "precondition: the purge re-anchored the chain")
		aktAssertValid(t, e, e.c)
		c2 := aktRotate(t, e)
		aktAssertValid(t, e, c2)
	})
}

// (3) A recorded break is carried over as a break: the new key does not
// re-notarise it, and the reason is the original failure, not a key epoch.
func TestAuditKeyTransition_CarriesFailureOver(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		tamperDescription(t, e.db, 3)
		id, started, err := e.c.StartAuditFullVerification(context.Background())
		require.NoError(t, err)
		require.True(t, started)
		waitAuditJob(t, e.c, id)
		require.Equal(t, AuditVerifyStatusBroken, incrVerify(t, e.c).Status)
		c2 := aktRotate(t, e)
		for range 3 {
			fcTick(t, e, c2)
		}
		r := incrVerify(t, c2)
		assert.Equal(t, AuditVerifyStatusBroken, r.Status)
		assert.NotContains(t, r.Reason, "other key epoch")
		assert.NotContains(t, r.Reason, aktTransitionText)
		v, err := c2.VerifyAuditChain(context.Background())
		require.NoError(t, err)
		assert.False(t, v.Valid, "a broken chain is never re-notarised under the new key")
	})
}

// (4) A discontinuity recorded before the key change stays.
func TestAuditKeyTransition_CarriesDiscontinuityOver(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		fcDeleteState(t, e.db)
		c1 := e.restart()
		fcTick(t, e, c1)
		assertDiscontinuity(t, e, c1, auditDiscDeleted)
		e.c = c1
		c2 := aktRotate(t, e)
		fcTick(t, e, c2)
		assertDiscontinuity(t, e, c2, auditDiscDeleted)
	})
}

// (5) The record is deleted after the change: the state names the
// transition, so it is a discontinuity.
func TestAuditKeyTransition_RecordMissing(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		aktRotate(t, e)
		require.NoError(t, e.db.Where(&models.SystemMetadata{Key: auditKeyTransitionsKey}).Delete(&models.SystemMetadata{}).Error)
		c3 := aktOnKey(t, e, aktNewKey, "v2", true)
		fcTick(t, e, c3)
		assertDiscontinuity(t, e, c3, "key transition")
	})
}

// (6) The record's new-key MAC is forged (one byte flipped).
func TestAuditKeyTransition_RecordForged(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		aktRotate(t, e)
		val := aktTransitionsValue(t, e.db)
		last := val[len(val)-1]
		flip := byte('0')
		if last == '0' {
			flip = '1'
		}
		aktSetTransitionsValue(t, e.db, val[:len(val)-1]+string(flip))
		c3 := aktOnKey(t, e, aktNewKey, "v2", false)
		_, err := c3.CompleteAuditKeyTransition(context.Background())
		require.Error(t, err, "a forged record is never completed")
		fcTick(t, e, c3)
		assertDiscontinuity(t, e, c3, "key transition")
	})
}

// (7) Wrong epoch: after a recorded v1 -> v2 change, the key changes again to
// v3 without a record (an older binary, or a relabel): the last record names
// neither the current epoch as new nor as old.
func TestAuditKeyTransition_RecordForWrongEpoch(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		aktRotate(t, e)
		c3 := aktOnKey(t, e, aktKey3, "v3", true)
		fcTick(t, e, c3)
		r := incrVerify(t, c3)
		assert.Equal(t, AuditVerifyStatusBroken, r.Status)
		assert.Contains(t, r.Reason, fcDiscontinuityText)
	})
}

// (8) A DB-only actor transplants a pending record that names the current key
// as new and old state it never had: the new-key MAC does not verify.
func TestAuditKeyTransition_ForgedPendingRecordNotCompleted(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		// Prepared for another new key (the actor's guess), then presented to a
		// server on aktNewKey.
		require.NoError(t, e.c.PrepareAuditKeyTransition(ctx, []byte("attacker-guess-32-bytes-long----"), "v2"))
		c2 := e.restart()
		c2.SetAuditCheckpointKey(aktNewKey, "v2")
		_, err := c2.CompleteAuditKeyTransition(ctx)
		require.Error(t, err, "a record whose new-key MAC fails is never completed")
		c2.SeedAuditWatermark(ctx)
		fcTick(t, e, c2)
		r := incrVerify(t, c2)
		assert.Equal(t, AuditVerifyStatusBroken, r.Status)
		assert.Contains(t, r.Reason, fcDiscontinuityText)
	})
}

// (9) The state row is edited between prepare and complete: completion
// refuses and the status stays fail-closed.
func TestAuditKeyTransition_StateChangedAfterPrepareFailsClosed(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		require.NoError(t, e.c.PrepareAuditKeyTransition(ctx, aktNewKey, "v2"))
		fcTick(t, e, e.c) // the old-key process saves the state again
		c2 := e.restart()
		c2.SetAuditCheckpointKey(aktNewKey, "v2")
		_, err := c2.CompleteAuditKeyTransition(ctx)
		require.Error(t, err)
		c2.SeedAuditWatermark(ctx)
		fcTick(t, e, c2)
		r := incrVerify(t, c2)
		assert.Equal(t, AuditVerifyStatusBroken, r.Status)
		assert.Contains(t, r.Reason, fcDiscontinuityText)
	})
}

// (10) Kill after prepare, before the key files commit: the server stays on
// the old key, the pending record is ignored, and a retried rotation
// replaces it rather than appending after it.
func TestAuditKeyTransition_KillAfterPrepare(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		require.NoError(t, e.c.PrepareAuditKeyTransition(ctx, aktNewKey, "v2"))
		c1 := aktOnKey(t, e, []byte("reanchor-test-key-32-bytes-long"), "v1", true)
		aktAssertValid(t, e, c1)
		e.c = c1
		c2 := aktRotate(t, e)
		assert.Equal(t, 1, strings.Count(aktTransitionsValue(t, e.db), "\n")+1, "the retry replaced the pending record")
		aktAssertValid(t, e, c2)
	})
}

// (11) Kill after the key files commit, before completion: the next process
// on the new key reads no alarm even before it completes, and completing
// (server start) leaves it valid.
func TestAuditKeyTransition_KillAfterKeyCommit(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		require.NoError(t, e.c.PrepareAuditKeyTransition(ctx, aktNewKey, "v2"))
		c2 := aktOnKey(t, e, aktNewKey, "v2", false)
		r := incrVerify(t, c2)
		assert.NotEqual(t, AuditVerifyStatusBroken, r.Status, "the old state is accepted through the record: %s", r.Reason)
		done, err := c2.CompleteAuditKeyTransition(ctx)
		require.NoError(t, err)
		assert.True(t, done)
		aktAssertValid(t, e, c2)
	})
}

// (12) Kill at every step inside completion: the retry (next server start)
// completes it, and no state in between reads broken.
func TestAuditKeyTransition_KillInsideComplete(t *testing.T) {
	for _, step := range []string{aktStepAnchor, aktStepHighWater, aktStepCheckpoint, aktStepState} {
		t.Run(step, func(t *testing.T) {
			fcRun(t, func(t *testing.T, e *fcEnv) {
				ctx := context.Background()
				fcCertify(t, e)
				require.NoError(t, e.c.PrepareAuditKeyTransition(ctx, aktNewKey, "v2"))
				c2 := e.restart()
				c2.SetAuditCheckpointKey(aktNewKey, "v2")
				killed := errors.New("killed at " + step)
				c2.auditKeyTransitionHook = func(s string) error {
					if s == step {
						return killed
					}
					return nil
				}
				_, err := c2.CompleteAuditKeyTransition(ctx)
				require.ErrorIs(t, err, killed)
				c3 := aktOnKey(t, e, aktNewKey, "v2", false)
				r := incrVerify(t, c3)
				assert.NotEqual(t, AuditVerifyStatusBroken, r.Status, "half-completed: %s", r.Reason)
				done, err := c3.CompleteAuditKeyTransition(ctx)
				require.NoError(t, err)
				assert.True(t, done)
				aktAssertValid(t, e, c3)
				assert.Equal(t, int64(1), countEvents(t, e.db, auditKeyTransitionEvent), "a retried completion appends the in-chain record once")
			})
		})
	}
}

// (13) Completion is idempotent: a second run (every server start) is a no-op.
func TestAuditKeyTransition_CompleteIdempotent(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		c2 := aktRotate(t, e)
		done, err := c2.CompleteAuditKeyTransition(ctx)
		require.NoError(t, err)
		assert.False(t, done)
		aktAssertValid(t, e, c2)
	})
}

// (14) Two rotations in a row chain their records (seq, prev).
func TestAuditKeyTransition_TwoRotations(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		c2 := aktRotate(t, e)
		fcTick(t, e, c2)
		require.NoError(t, c2.PrepareAuditKeyTransition(ctx, aktKey3, "v3"))
		c3 := aktOnKey(t, e, aktKey3, "v3", true)
		recs, err := parseAuditKeyTransitions(aktTransitionsValue(t, e.db))
		require.NoError(t, err)
		require.Len(t, recs, 2)
		assert.Equal(t, recs[0].digest(), recs[1].Prev)
		aktAssertValid(t, e, c3)
	})
}

// (15) The pre-rotation state row is put back after completion (a DB-write
// actor erasing what was recorded since): the record still names its digest,
// but the completion event proves the state was saved under the new key, so
// the old row is not accepted and completion does not re-sign it.
func TestAuditKeyTransition_OldStateRowPutBackAfterCompletion(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		require.NoError(t, e.c.PrepareAuditKeyTransition(ctx, aktNewKey, "v2"))
		prepared := fcStateValue(t, e.db)
		c2 := aktOnKey(t, e, aktNewKey, "v2", true)
		fcTick(t, e, c2)
		fcSetStateValue(t, e.db, prepared)
		c3 := e.restart()
		c3.SetAuditCheckpointKey(aktNewKey, "v2")
		_, err := c3.CompleteAuditKeyTransition(ctx)
		require.Error(t, err, "the old row is not re-signed")
		c3.SeedAuditWatermark(ctx)
		fcTick(t, e, c3)
		assertDiscontinuity(t, e, c3, auditDiscOtherEpoch)
	})
}

// (16) A DB-write actor garbles the record list to block a key change (which
// may be the response to a compromise): the change still goes through, and the
// damage stays a sticky discontinuity.
func TestAuditKeyTransition_DamagedRecordDoesNotBlockKeyChange(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		require.NoError(t, e.c.storage.SetSystemMetadata(ctx, auditKeyTransitionsKey, "akt-v1\x1fnot-a-record"))
		require.NoError(t, e.c.PrepareAuditKeyTransition(ctx, aktNewKey, "v2"))
		recs, err := parseAuditKeyTransitions(aktTransitionsValue(t, e.db))
		require.NoError(t, err)
		require.Len(t, recs, 1)
		assert.NotEmpty(t, recs[0].Reset)
		c2 := aktOnKey(t, e, aktNewKey, "v2", true)
		fcTick(t, e, c2)
		assertDiscontinuity(t, e, c2, "key transition")
	})
}

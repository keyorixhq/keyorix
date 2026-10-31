// audit_seal_resume_key_change_test.go — an acceptance left unfinished and
// then a key change (rotate-kek, migrate-provider) can still be resumed on the
// new key (#3814, AUDIT-SEAL-TAILS-2). Before, the resume refused because the
// acceptance's own not-yet-rewritten checkpoint and high-water mark, signed
// under the previous key and the seal list before the acceptance,
// "authenticate neither under seal #1 nor before it" under the new key.
//
// Every case runs on SQLite and, with KEYORIX_TEST_PG_DSN, on PostgreSQL.
package core

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sealCrashThenKeyChange: a certified deployment loses row 3, accept-loss
// stops after step, a key change from v1 to v2 is prepared and its key files
// commit (the command's completion and a server start run on v2), and a
// fresh process on v2 is returned for the operator's re-run. tamper, when
// set, runs before the key change is prepared.
func sealCrashThenKeyChange(t *testing.T, e *fcEnv, step, witness string, tamper func()) (*KeyorixCore, *AuditLossPlan) {
	t.Helper()
	ctx := context.Background()
	if witness != "" {
		withWitness(e.c, witness)
	}
	fcCertify(t, e)
	resume := sealDeleteRow(t, e, e.c, 3)
	plan, err := e.c.PlanAuditLossAcceptance(ctx, sealReq(resume))
	require.NoError(t, err)
	require.NotNil(t, plan.Before, "precondition: the seal records a certification")
	crash := errors.New("crash")
	e.c.auditSealHook = func(s string) error {
		if s == step {
			return crash
		}
		return nil
	}
	_, err = e.c.AcceptAuditLoss(ctx, plan)
	require.ErrorIs(t, err, crash)

	if tamper != nil {
		tamper()
	}
	old := e.restart()
	if witness != "" {
		withWitness(old, witness)
	}
	require.NoError(t, old.PrepareAuditKeyTransition(ctx, aktNewKey, "v2"))
	for range 2 { // the command's completion, then a server start
		c := e.restart()
		c.SetAuditCheckpointKey(aktNewKey, "v2")
		_, _ = c.CompleteAuditKeyTransition(ctx) // may stop while the seal is pending
		c.SeedAuditWatermark(ctx)
	}
	c := e.restart()
	c.SetAuditCheckpointKey(aktNewKey, "v2")
	if witness != "" {
		withWitness(c, witness)
	}
	return c, plan
}

// (6) #3814: an honest crash at any step of accept-loss, followed by a key
// change, resumes on the new key, completes, and the chain then reads sealed
// on every view (the key transition completes too).
func TestAuditSeal_ResumeAfterKeyChange(t *testing.T) {
	for _, witness := range []bool{false, true} {
		for _, step := range []string{"record", "event", "checkpoint", "high-water"} {
			name := step
			if witness {
				name += "/witness"
			}
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				fcRun(t, func(t *testing.T, e *fcEnv) {
					ctx := context.Background()
					w := ""
					if witness {
						w = filepath.Join(t.TempDir(), ".audit-highwater-witness")
					}
					c, plan := sealCrashThenKeyChange(t, e, step, w, nil)

					again, err := sealResumePlan(t, c, sealReq())
					require.NoError(t, err, "a re-run on the new key resumes the acceptance")
					require.True(t, again.Resume)
					assert.Equal(t, plan.seal.digest(), again.seal.digest(), "the same seal is completed, no new record")
					_, err = c.AcceptAuditLoss(ctx, again)
					require.NoError(t, err)

					s := aktOnKey(t, e, aktNewKey, "v2", true) // the next server start
					if witness {
						withWitness(s, w)
					}
					assertSealed(t, e, s, 1)
					assert.Equal(t, int64(1), countEvents(t, e.db, auditKeyTransitionEvent), "the key transition completed")
					if witness {
						hw := untrustedMeta(t, e.db, auditHighWaterKey)
						assert.Equal(t, hw, readWitnessFile(t, w), "the witness mirrors the mark")
					}
				})
			})
		}
	}
}

// (6) Two key changes before the re-run (v1 to v2 to v3): the second prepare,
// on v2, follows the naming of the transition into v2, so the resume on v3
// still tells the acceptance's own v1 artifacts apart.
func TestAuditSeal_ResumeAfterTwoKeyChanges(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		c, _ := sealCrashThenKeyChange(t, e, "record", "", nil)
		require.NoError(t, c.PrepareAuditKeyTransition(ctx, aktKey3, "v3"))
		for range 2 {
			p := e.restart()
			p.SetAuditCheckpointKey(aktKey3, "v3")
			_, _ = p.CompleteAuditKeyTransition(ctx)
		}
		c3 := e.restart()
		c3.SetAuditCheckpointKey(aktKey3, "v3")
		again, err := sealResumePlan(t, c3, sealReq())
		require.NoError(t, err, "a re-run on the third key resumes the acceptance")
		require.True(t, again.Resume)
		_, err = c3.AcceptAuditLoss(ctx, again)
		require.NoError(t, err)
		assertSealed(t, e, aktOnKey(t, e, aktKey3, "v3", true), 1)
	})
}

// audit_seal_resume_witness_test.go — a resumed acceptance reads the host's
// high-water witness file and never lowers it (REVIEW-3757-DEEP-2 F1). The
// witness only exists on SQLite installs, but it is a plain file, so every
// case runs on SQLite and, with KEYORIX_TEST_PG_DSN, on PostgreSQL.
package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// withWitness points c at the witness file w, as server startup and the admin
// command do on a SQLite install.
func withWitness(c *KeyorixCore, w string) *KeyorixCore {
	c.SetAuditHighWaterWitnessPath(w)
	return c
}

func readWitnessFile(t *testing.T, w string) string {
	t.Helper()
	b, err := os.ReadFile(w)
	require.NoError(t, err)
	return string(b)
}

// (5) A DB-level actor holding a copy from before the acceptance (the
// runbook's evidence copy, or any routine backup) cuts the tail certified
// after a completed seal, deletes the newer checkpoints and puts back the
// copy's high-water mark and verification state. Inside the database that
// reads as an acceptance stopped after its checkpoint, but the host witness
// still certifies the cut rows under the seal: the re-run refuses and writes
// nothing, the witness included.
func TestAuditSeal_ResumeRefusesRollbackBelowWitness(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		w := filepath.Join(t.TempDir(), ".audit-highwater-witness")
		withWitness(e.c, w)
		fcCertify(t, e)
		resume := sealDeleteRow(t, e, e.c, 3)
		hwCopy, ok, err := e.c.storage.GetSystemMetadata(ctx, auditHighWaterKey)
		require.NoError(t, err)
		require.True(t, ok)
		stCopy := fcStateValue(t, e.db)

		sealAccept(t, e.c, sealReq(resume))
		c := withWitness(e.restart(), w)
		assertSealed(t, e, c, 1)
		reseal, err := c.storage.LatestAuditCheckpoint(ctx)
		require.NoError(t, err)
		for range 4 {
			fcTick(t, e, c) // certified activity after the seal
		}
		cp, err := c.storage.LatestAuditCheckpoint(ctx)
		require.NoError(t, err)
		require.Greater(t, cp.ID, reseal.ID, "precondition: certified activity after the seal")
		witness := readWitnessFile(t, w)
		wcp, b, _, parsed := parseAuditHighWaterSealed(witness)
		require.True(t, parsed)
		require.Equal(t, 1, b.N, "precondition: the witness is under the seal")
		require.Equal(t, cp.ChainedEvents, wcp.ChainedEvents, "precondition: the witness certifies the post-seal tail")

		require.NoError(t, e.db.Exec("DELETE FROM audit_events WHERE id >= ?", cp.HeadID-2).Error)
		require.NoError(t, e.db.Where("id > ?", reseal.ID).Delete(&models.AuditCheckpoint{}).Error)
		require.NoError(t, e.db.Model(&models.SystemMetadata{}).Where(&models.SystemMetadata{Key: auditHighWaterKey}).Update("value", hwCopy).Error)
		fcSetStateValue(t, e.db, stCopy)
		good := sealsValue(t, e.db)

		sealRefused(t, withWitness(e.restart(), w), sealReq(), "the host's high-water witness file certifies")
		assert.Equal(t, witness, readWitnessFile(t, w), "the witness is not lowered")
		assert.Equal(t, good, sealsValue(t, e.db), "nothing is written: the seal record is unchanged")
		after, err := e.restart().storage.LatestAuditCheckpoint(ctx)
		require.NoError(t, err)
		assert.Equal(t, reseal.ID, after.ID, "nothing is written: no re-seal checkpoint")
	})
}

// (5) A witness that exists but cannot be read as a mark, or that does not
// authenticate, is not "no witness" (the rule `admin restore` applies): an
// acceptance stopped after its event refuses to resume over it.
func TestAuditSeal_ResumeRefusesUnreadableWitness(t *testing.T) {
	for _, variant := range []string{"garbage", "directory", "forged"} {
		t.Run(variant, func(t *testing.T) {
			fcRun(t, func(t *testing.T, e *fcEnv) {
				ctx := context.Background()
				w := filepath.Join(t.TempDir(), ".audit-highwater-witness")
				withWitness(e.c, w)
				fcCertify(t, e)
				resume := sealDeleteRow(t, e, e.c, 3)
				plan, err := e.c.PlanAuditLossAcceptance(ctx, sealReq(resume))
				require.NoError(t, err)
				crash := errors.New("crash")
				e.c.auditSealHook = func(s string) error {
					if s == "event" {
						return crash
					}
					return nil
				}
				_, err = e.c.AcceptAuditLoss(ctx, plan)
				require.ErrorIs(t, err, crash)

				switch variant {
				case "garbage":
					require.NoError(t, os.WriteFile(w, []byte("garbage"), 0o600))
				case "directory":
					require.NoError(t, os.Remove(w))
					require.NoError(t, os.Mkdir(w, 0o700))
				case "forged":
					v := readWitnessFile(t, w)
					require.NoError(t, os.WriteFile(w, []byte(v[:len(v)-4]+"0000"), 0o600))
				}
				want := map[string]string{"garbage": "does not parse", "directory": "not a regular file", "forged": "authenticates neither"}[variant]
				sealRefused(t, withWitness(e.restart(), w), sealReq(), want)
			})
		})
	}
}

// An honest crash at any step still resumes with the witness in place (it is
// under the binding before the seal, or under the seal certifying the sealed
// chain), the plan names who recorded the seal and when, and the completed
// acceptance leaves the witness equal to the mark.
func TestAuditSeal_CrashAtEveryStepResumesWithWitness(t *testing.T) {
	for _, step := range []string{"record", "event", "checkpoint", "high-water"} {
		t.Run(step, func(t *testing.T) {
			t.Parallel()
			fcRun(t, func(t *testing.T, e *fcEnv) {
				ctx := context.Background()
				w := filepath.Join(t.TempDir(), ".audit-highwater-witness")
				withWitness(e.c, w)
				fcCertify(t, e)
				resume := sealDeleteRow(t, e, e.c, 3)
				plan, err := e.c.PlanAuditLossAcceptance(ctx, sealReq(resume))
				require.NoError(t, err)
				crash := errors.New("crash")
				e.c.auditSealHook = func(s string) error {
					if s == step {
						return crash
					}
					return nil
				}
				_, err = e.c.AcceptAuditLoss(ctx, plan)
				require.ErrorIs(t, err, crash)
				fcTick(t, e, withWitness(e.restart(), w)) // a server ran before the operator re-ran the command

				c := withWitness(e.restart(), w)
				again, err := sealResumePlan(t, c, sealReq())
				require.NoError(t, err, "a re-run resumes")
				require.True(t, again.Resume)
				desc := strings.Join(again.Describe(), "\n")
				assert.Contains(t, desc, "recorded "+plan.seal.At.Format("2006-01-02T15:04:05Z07:00"))
				assert.Contains(t, desc, `by "ops-oncall"`)
				assert.Contains(t, desc, `"INC-42: disk restore lost rows"`)
				assert.Contains(t, desc, "did not start")
				_, err = c.AcceptAuditLoss(ctx, again)
				require.NoError(t, err)
				mark, ok, err := c.storage.GetSystemMetadata(ctx, auditHighWaterKey)
				require.NoError(t, err)
				require.True(t, ok)
				assert.Equal(t, mark, readWitnessFile(t, w), "the witness mirrors the re-seal mark")
				assertSealed(t, e, withWitness(e.restart(), w), 1)
			})
		})
	}
}

// (5) The re-seal never lowers a witness that authenticates under the current
// seal list: it certified rows written after this seal, which the seal did
// not accept. The check runs before anything is written.
func TestAuditSeal_ResealKeepsHigherWitness(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		w := filepath.Join(t.TempDir(), ".audit-highwater-witness")
		withWitness(e.c, w)
		fcCertify(t, e)
		sealAccept(t, e.c, sealReq(sealDeleteRow(t, e, e.c, 3)))
		c := withWitness(e.restart(), w)
		assertSealed(t, e, c, 1)
		for range 4 {
			fcTick(t, e, c)
		}
		cp, err := c.storage.LatestAuditCheckpoint(ctx)
		require.NoError(t, err)
		witness := readWitnessFile(t, w)
		require.NoError(t, e.db.Exec("DELETE FROM audit_events WHERE id >= ?", cp.HeadID-2).Error)

		_, _, err = withWitness(e.restart(), w).resealAuditCheckpoint(ctx, false)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "witness")
		assert.Equal(t, witness, readWitnessFile(t, w), "the witness is not lowered")
		after, err := e.restart().storage.LatestAuditCheckpoint(ctx)
		require.NoError(t, err)
		assert.Equal(t, cp.ID, after.ID, "no checkpoint is written")
	})
}

// audit_seal_resume_certs_test.go — a resumed acceptance does not treat a
// removed or garbled certification as "no certification" (REVIEW-3757-DEEP-1
// H1). Every case runs on SQLite and, with KEYORIX_TEST_PG_DSN, on PostgreSQL.
package core

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// (5) TestAuditSeal_ResumeRefusesPostSealTruncation, plus the DB-level actor
// deleting or garbling the checkpoints and the high-water mark that certified
// the cut rows, or putting back the authentic mark the acceptance wrote before
// the server run (replay: every checkpoint and mark left then authenticates
// and holds, and the state that run saved is older than the mark). The
// verification state's pin, signed under the seal, still certifies the cut
// rows, and a missing or garbled certification is not the acceptance's own
// half-written artifact: the re-run refuses and writes nothing.
func TestAuditSeal_ResumeRefusesRemovedCertifications(t *testing.T) {
	for _, variant := range []string{"delete", "garble", "replay"} {
		t.Run(variant, func(t *testing.T) {
			fcRun(t, func(t *testing.T, e *fcEnv) {
				ctx := context.Background()
				c, _ := sealedEnv(t, e)
				assertSealed(t, e, c, 1)
				reseal, err := c.storage.LatestAuditCheckpoint(ctx)
				require.NoError(t, err)
				resealMark, ok, err := c.storage.GetSystemMetadata(ctx, auditHighWaterKey)
				require.NoError(t, err)
				require.True(t, ok)
				for range 4 {
					fcTick(t, e, c) // certified activity after the seal
				}
				cp, err := c.storage.LatestAuditCheckpoint(ctx)
				require.NoError(t, err)
				require.Greater(t, cp.ID, reseal.ID, "precondition: certified activity after the seal")
				require.True(t, c.checkpointSignatureValid(cp))
				require.NoError(t, e.db.Exec("DELETE FROM audit_events WHERE id >= ?", cp.HeadID-2).Error)

				tamper := func() {
					switch variant {
					case "delete":
						require.NoError(t, e.db.Where("id > ?", reseal.ID).Delete(&models.AuditCheckpoint{}).Error)
						require.NoError(t, e.db.Where(&models.SystemMetadata{Key: auditHighWaterKey}).Delete(&models.SystemMetadata{}).Error)
					case "garble":
						require.NoError(t, e.db.Model(&models.AuditCheckpoint{}).Where("id > ?", reseal.ID).Update("signature", strings.Repeat("0", 64)).Error)
						require.NoError(t, e.db.Model(&models.SystemMetadata{}).Where(&models.SystemMetadata{Key: auditHighWaterKey}).Update("value", "garbage").Error)
					case "replay":
						require.NoError(t, e.db.Where("id > ?", reseal.ID).Delete(&models.AuditCheckpoint{}).Error)
						require.NoError(t, e.db.Model(&models.SystemMetadata{}).Where(&models.SystemMetadata{Key: auditHighWaterKey}).Update("value", resealMark).Error)
					}
				}
				if variant == "replay" {
					tamper() // before the server run: the state it saves binds the replayed trail
				}
				good := sealsValue(t, e.db)
				parts := strings.Split(good, auditVerifyStateSep)
				payload, err := base64.RawURLEncoding.DecodeString(parts[1])
				require.NoError(t, err)
				parts[1] = base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(payload), "ops-oncall", "someone-else", 1)))
				setSealsValue(t, e.db, strings.Join(parts, auditVerifyStateSep))
				fcTick(t, e, e.restart()) // a server records the seal-record discontinuity
				setSealsValue(t, e.db, good)
				if variant != "replay" {
					tamper()
				}
				latest, err := e.restart().storage.LatestAuditCheckpoint(ctx)
				require.NoError(t, err)

				want := map[string]string{"delete": "high-water mark is missing", "garble": "authenticates neither", "replay": "verification state is untrusted"}[variant]
				sealRefused(t, e.restart(), sealReq(), want)
				assert.Equal(t, good, sealsValue(t, e.db), "nothing is written: the seal record is unchanged")
				after, err := e.restart().storage.LatestAuditCheckpoint(ctx)
				require.NoError(t, err)
				assert.Equal(t, latest.ID, after.ID, "nothing is written: no re-seal checkpoint")
				assert.NotEqual(t, AuditVerifyStatusSealed, incrVerify(t, e.restart()).Status)
			})
		})
	}
}

// (5) As above for a seal that recorded no certification before its loss (so
// a missing mark is not by itself proof of tampering): the checkpoints after
// the re-seal and the mark are deleted, and the re-seal checkpoint still
// holds. Only the state's pin, signed under the seal and carried over by the
// server run that recorded the seal-record discontinuity, shows the cut.
func TestAuditSeal_ResumeRefusesRemovedCertificationsUncertifiedSeal(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		logIncrEvents(t, e.c, e.clk, 6)
		resume := sealDeleteRow(t, e, e.c, 3)
		plan, err := e.c.PlanAuditLossAcceptance(ctx, sealReq(resume))
		require.NoError(t, err)
		require.Nil(t, plan.Before, "precondition: nothing certified the chain before the loss")
		_, err = e.c.AcceptAuditLoss(ctx, plan)
		require.NoError(t, err)
		c := e.restart()
		reseal, err := c.storage.LatestAuditCheckpoint(ctx)
		require.NoError(t, err)
		for range 4 {
			fcTick(t, e, c) // certified activity after the seal
		}
		cp, err := c.storage.LatestAuditCheckpoint(ctx)
		require.NoError(t, err)
		require.Greater(t, cp.ID, reseal.ID, "precondition: certified activity after the seal")
		require.NoError(t, e.db.Exec("DELETE FROM audit_events WHERE id >= ?", cp.HeadID-2).Error)

		good := sealsValue(t, e.db)
		parts := strings.Split(good, auditVerifyStateSep)
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, err)
		parts[1] = base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(payload), "ops-oncall", "someone-else", 1)))
		setSealsValue(t, e.db, strings.Join(parts, auditVerifyStateSep))
		fcTick(t, e, e.restart()) // a server records the seal-record discontinuity
		setSealsValue(t, e.db, good)
		require.NoError(t, e.db.Where("id > ?", reseal.ID).Delete(&models.AuditCheckpoint{}).Error)
		require.NoError(t, e.db.Where(&models.SystemMetadata{Key: auditHighWaterKey}).Delete(&models.SystemMetadata{}).Error)

		sealRefused(t, e.restart(), sealReq(), "the signed verification state")
		assert.Equal(t, good, sealsValue(t, e.db), "nothing is written: the seal record is unchanged")
		after, err := e.restart().storage.LatestAuditCheckpoint(ctx)
		require.NoError(t, err)
		assert.Equal(t, reseal.ID, after.ID, "nothing is written: no re-seal checkpoint")
	})
}

// (5) An acceptance stopped after its event (the state is still behind the
// seal, so its pin does not apply) resumes over its own half-written
// artifacts only: a latest checkpoint or high-water mark that authenticates
// under neither the seal list nor the one before it, or a mark deleted
// although the seal recorded a certification, is refused.
func TestAuditSeal_ResumeRefusesUnaccountedArtifacts(t *testing.T) {
	for _, variant := range []string{"checkpoint-garbled", "high-water-garbled", "high-water-deleted"} {
		t.Run(variant, func(t *testing.T) {
			fcRun(t, func(t *testing.T, e *fcEnv) {
				ctx := context.Background()
				fcCertify(t, e)
				resume := sealDeleteRow(t, e, e.c, 3)
				plan, err := e.c.PlanAuditLossAcceptance(ctx, sealReq(resume))
				require.NoError(t, err)
				require.NotNil(t, plan.Before, "precondition: the seal records a certification")
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
				case "checkpoint-garbled":
					cp, err := e.restart().storage.LatestAuditCheckpoint(ctx)
					require.NoError(t, err)
					require.NoError(t, e.db.Model(&models.AuditCheckpoint{}).Where("id = ?", cp.ID).Update("signature", strings.Repeat("0", 64)).Error)
				case "high-water-garbled":
					require.NoError(t, e.db.Model(&models.SystemMetadata{}).Where(&models.SystemMetadata{Key: auditHighWaterKey}).Update("value", "garbage").Error)
				case "high-water-deleted":
					require.NoError(t, e.db.Where(&models.SystemMetadata{Key: auditHighWaterKey}).Delete(&models.SystemMetadata{}).Error)
				}
				want := map[string]string{"checkpoint-garbled": "latest checkpoint", "high-water-garbled": "high-water mark authenticates neither",
					"high-water-deleted": "high-water mark is missing"}[variant]
				sealRefused(t, e.restart(), sealReq(), want)
				assert.NotEqual(t, AuditVerifyStatusSealed, incrVerify(t, e.restart()).Status)
			})
		})
	}
}

// (3) A high-water mark deleted beside a signed checkpoint is tampering, not a
// row loss: accepting over it would under-measure what the seal records
// (REVIEW-3757-DEEP-1 L1).
func TestAuditSeal_RefusesMissingHighWater(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		resume := sealDeleteRow(t, e, e.c, 3)
		require.NoError(t, e.db.Where(&models.SystemMetadata{Key: auditHighWaterKey}).Delete(&models.SystemMetadata{}).Error)
		sealRefused(t, e.restart(), sealReq(resume), "high-water mark is missing")
	})
}

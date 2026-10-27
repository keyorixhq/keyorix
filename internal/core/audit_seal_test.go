// audit_seal_test.go — accepting a proven audit-row loss (audit_seal.go,
// audit_seal_accept.go; `admin audit accept-loss`, AUDIT-ACCEPT-LOSS-1). The
// eight constraints of docs/design/recovery-options.md §2 are the checklist:
// a sealed chain is never valid again (1), the seal refuses anything but a
// proven loss at exactly the named ids (3), the record pins the evidence (4),
// tampering with it reads broken (5), it survives a key change (6) and every
// later checkpoint is bound to it (7).
//
// Every case runs on SQLite and, with KEYORIX_TEST_PG_DSN, on PostgreSQL.
package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const sealEvidence = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func sealReq(ids ...uint) AuditLossRequest {
	return AuditLossRequest{BrokenIDs: ids, Operator: "ops-oncall", OSUser: "keyorix", Reason: "INC-42: disk restore lost rows", Evidence: sealEvidence}
}

// sealDeleteRow deletes one audit row and returns the id the walk now breaks at.
func sealDeleteRow(t *testing.T, e *fcEnv, c *KeyorixCore, id uint) uint {
	t.Helper()
	require.NoError(t, e.db.Exec("DELETE FROM audit_events WHERE id = ?", id).Error)
	v, err := c.VerifyAuditChain(context.Background())
	require.NoError(t, err)
	require.False(t, v.Valid, "precondition: a deleted row reads broken")
	require.NotNil(t, v.FirstBrokenID)
	return *v.FirstBrokenID
}

func sealAccept(t *testing.T, c *KeyorixCore, req AuditLossRequest) *AuditLossResult {
	t.Helper()
	plan, err := c.PlanAuditLossAcceptance(context.Background(), req)
	require.NoError(t, err)
	res, err := c.AcceptAuditLoss(context.Background(), plan)
	require.NoError(t, err)
	return res
}

func sealRefused(t *testing.T, c *KeyorixCore, req AuditLossRequest, want string) {
	t.Helper()
	_, err := c.PlanAuditLossAcceptance(context.Background(), req)
	require.ErrorIs(t, err, ErrAuditLossRefused)
	assert.Contains(t, err.Error(), want)
}

// sealSettle runs ticks (and a full job) on a fresh process until the
// incremental status leaves not_proven, and returns it.
func sealSettle(t *testing.T, e *fcEnv, c *KeyorixCore) *AuditVerifyReport {
	t.Helper()
	for range 6 {
		fcTick(t, e, c)
		if r := incrVerify(t, c); r.Status != AuditVerifyStatusNotProven {
			return r
		}
	}
	return incrVerify(t, c)
}

// assertSealed: every view says sealed (never valid), the walk verifies.
func assertSealed(t *testing.T, e *fcEnv, c *KeyorixCore, seals int) {
	t.Helper()
	ctx := context.Background()
	r := sealSettle(t, e, c)
	assert.Equal(t, AuditVerifyStatusSealed, r.Status, "%s %s", r.Reason, r.NotProvenReason)
	assert.False(t, r.Valid)
	assert.Contains(t, r.StateReason, "sealed")
	p, err := c.AuditVerificationStatus(ctx)
	require.NoError(t, err)
	assert.Equal(t, AuditVerifyStatusSealed, p.Status, "posture: %s %s", p.Reason, p.NotProvenReason)
	assert.False(t, p.Valid)
	v, err := c.VerifyAuditChain(ctx)
	require.NoError(t, err)
	assert.True(t, v.Valid, v.Reason)
	assert.Equal(t, seals, v.Seals)
	assert.Equal(t, AuditVerifyStatusSealed, fullAuditVerifyReport(v).Status)
	id := startFullJobWhenFree(t, c)
	j := waitAuditJob(t, c, id)
	require.NotNil(t, j.Result)
	assert.Equal(t, AuditVerifyStatusSealed, j.Result.Status, "full job: %s", j.Result.Reason)
	assert.False(t, j.Result.Valid)
	// A full verification does not make it valid either.
	assert.Equal(t, AuditVerifyStatusSealed, incrVerify(t, c).Status)
	assert.Equal(t, int64(seals), countEvents(t, e.db, auditSealEvent), "one in-chain event per acceptance")
}

// assertBroken: the full walk reads broken now, the incremental status within
// a rolling cycle (a row below the checkpoint head is the cycle's to find).
func assertBroken(t *testing.T, e *fcEnv, c *KeyorixCore) {
	t.Helper()
	v, err := c.VerifyAuditChain(context.Background())
	require.NoError(t, err)
	assert.False(t, v.Valid, "walk must read broken")
	assert.NotEqual(t, AuditVerifyStatusSealed, fullAuditVerifyReport(v).Status)
	for range 6 {
		if incrVerify(t, c).Status == AuditVerifyStatusBroken {
			break
		}
		fcTick(t, e, c)
	}
	r := incrVerify(t, c)
	assert.Equal(t, AuditVerifyStatusBroken, r.Status, "%s %s", r.Reason, r.NotProvenReason)
	p, err := c.AuditVerificationStatus(context.Background())
	require.NoError(t, err)
	assert.Equal(t, AuditVerifyStatusBroken, p.Status, "posture: %s %s", p.Reason, p.NotProvenReason)
}

func sealsValue(t *testing.T, db *gorm.DB) string {
	t.Helper()
	var row models.SystemMetadata
	require.NoError(t, db.Where(&models.SystemMetadata{Key: auditSealsKey}).First(&row).Error)
	return row.Value
}

func setSealsValue(t *testing.T, db *gorm.DB, val string) {
	t.Helper()
	require.NoError(t, db.Model(&models.SystemMetadata{}).Where(&models.SystemMetadata{Key: auditSealsKey}).Update("value", val).Error)
}

// sealedEnv: a certified deployment with row 3 deleted and the gap accepted,
// running on a fresh process.
func sealedEnv(t *testing.T, e *fcEnv) (*KeyorixCore, uint) {
	t.Helper()
	fcCertify(t, e)
	resume := sealDeleteRow(t, e, e.c, 3)
	sealAccept(t, e.c, sealReq(resume))
	return e.restart(), resume
}

// (1, 3, 4) A deleted row: broken, then accepted at exactly the id where the
// walk breaks; afterwards every view reads sealed, never valid.
func TestAuditSeal_GapSealedNeverValid(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		cp, err := e.c.storage.LatestAuditCheckpoint(ctx)
		require.NoError(t, err)
		resume := sealDeleteRow(t, e, e.c, 3)
		require.Equal(t, uint(4), resume)
		assertBroken(t, e, e.c)

		sealRefused(t, e.c, sealReq(resume+1), "breaks at audit event #4, not at #5")
		plan, err := e.c.PlanAuditLossAcceptance(ctx, sealReq(resume))
		require.NoError(t, err)
		require.Len(t, plan.Gaps, 1)
		assert.Equal(t, uint(2), plan.Gaps[0].LastGoodID)
		assert.Equal(t, uint(4), plan.Gaps[0].ResumeID)
		require.NotNil(t, plan.Before)
		assert.GreaterOrEqual(t, plan.Before.Events, cp.ChainedEvents)
		assert.Equal(t, int64(1), plan.LostEvents, "one certified row is gone")
		assert.Contains(t, strings.Join(plan.Describe(), "\n"), "1 event(s) between audit event #2 and #4")

		res, err := e.c.AcceptAuditLoss(ctx, plan)
		require.NoError(t, err)
		assert.Equal(t, 1, res.Seq)

		c2 := e.restart()
		r := incrVerify(t, c2)
		assert.Equal(t, AuditVerifyStatusNotProven, r.Status, "not proven until a full verification after the acceptance: %s", r.Reason)
		assertSealed(t, e, c2, 1)
		assertSealed(t, e, e.restart(), 1)

		// The record pins the evidence (constraint 4).
		recs, err := parseAuditSeals(sealsValue(t, e.db))
		require.NoError(t, err)
		require.Len(t, recs, 1)
		s := recs[0]
		assert.Equal(t, "ops-oncall", s.Operator)
		assert.Equal(t, "keyorix", s.OSUser)
		assert.Equal(t, sealEvidence, s.Evidence)
		assert.Equal(t, "INC-42: disk restore lost rows", s.Reason)
		assert.NotEmpty(t, s.Gaps[0].LastGoodHash)
		assert.NotEmpty(t, s.Gaps[0].ResumeHash)
		assert.NotEmpty(t, s.Accepted)
	})
}

// (5) Deleting, altering, moving or replaying the seal record, or removing
// rows around the sealed gap, reads broken, never valid or sealed.
func TestAuditSeal_TamperWithSealReadsBroken(t *testing.T) {
	cases := []struct {
		name   string
		tamper func(t *testing.T, e *fcEnv, c *KeyorixCore, resume uint)
	}{
		{"deleted", func(t *testing.T, e *fcEnv, _ *KeyorixCore, _ uint) {
			require.NoError(t, e.db.Where(&models.SystemMetadata{Key: auditSealsKey}).Delete(&models.SystemMetadata{}).Error)
		}},
		{"altered", func(t *testing.T, e *fcEnv, _ *KeyorixCore, _ uint) {
			parts := strings.Split(sealsValue(t, e.db), auditVerifyStateSep)
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			require.NoError(t, err)
			payload = []byte(strings.Replace(string(payload), "ops-oncall", "someone-else", 1))
			parts[1] = base64.RawURLEncoding.EncodeToString(payload)
			setSealsValue(t, e.db, strings.Join(parts, auditVerifyStateSep))
		}},
		{"moved", func(t *testing.T, e *fcEnv, _ *KeyorixCore, _ uint) {
			parts := strings.Split(sealsValue(t, e.db), auditVerifyStateSep)
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			require.NoError(t, err)
			payload = []byte(strings.Replace(string(payload), `"resume_id":4`, `"resume_id":5`, 1))
			parts[1] = base64.RawURLEncoding.EncodeToString(payload)
			setSealsValue(t, e.db, strings.Join(parts, auditVerifyStateSep))
		}},
		{"gap widened", func(t *testing.T, e *fcEnv, _ *KeyorixCore, _ uint) {
			require.NoError(t, e.db.Exec("DELETE FROM audit_events WHERE id = 2").Error)
		}},
		{"resume row rewritten", func(t *testing.T, e *fcEnv, _ *KeyorixCore, resume uint) {
			tamperDescription(t, e.db, resume)
		}},
		{"seal event removed", func(t *testing.T, e *fcEnv, _ *KeyorixCore, _ uint) {
			require.NoError(t, e.db.Exec("DELETE FROM audit_events WHERE event_type = ?", auditSealEvent).Error)
		}},
		{"post-seal checkpoints and state rolled back", func(t *testing.T, e *fcEnv, _ *KeyorixCore, _ uint) {
			require.NoError(t, e.db.Where(&models.SystemMetadata{Key: auditSealsKey}).Delete(&models.SystemMetadata{}).Error)
			require.NoError(t, e.db.Exec("DELETE FROM audit_events WHERE event_type = ?", auditSealEvent).Error)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fcRun(t, func(t *testing.T, e *fcEnv) {
				c, resume := sealedEnv(t, e)
				assertSealed(t, e, c, 1)
				tc.tamper(t, e, c, resume)
				for _, p := range []*KeyorixCore{c, e.restart()} {
					assertBroken(t, e, p)
					fcTick(t, e, p)
					assertBroken(t, e, p)
				}
			})
		})
	}
}

// (5) A replayed, shorter seal list (the second acceptance dropped) reads
// broken.
func TestAuditSeal_ReplayedSealListReadsBroken(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		c, _ := sealedEnv(t, e)
		assertSealed(t, e, c, 1)
		one := sealsValue(t, e.db)
		resume := sealDeleteRow(t, e, c, 7)
		sealAccept(t, c, sealReq(resume))
		c2 := e.restart()
		assertSealed(t, e, c2, 2)
		setSealsValue(t, e.db, one)
		assertBroken(t, e, c2)
		assertBroken(t, e, e.restart())
	})
}

// (3) Anything but a proven loss at the named id is refused.
func TestAuditSeal_RefusesWhatIsNotALoss(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		sealRefused(t, e.c, sealReq(4), "not the head")
		sealRefused(t, e.c, AuditLossRequest{BrokenIDs: []uint{4}}, "operator name")

		tamperDescription(t, e.db, 4)
		sealRefused(t, e.c, sealReq(4), "modified")
	})
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		resume := sealDeleteRow(t, e, e.c, 3)
		// The high-water mark garbled: an unauthenticated store.
		require.NoError(t, e.db.Model(&models.SystemMetadata{}).Where(&models.SystemMetadata{Key: auditHighWaterKey}).Update("value", "garbage").Error)
		sealRefused(t, e.c, sealReq(resume), "malformed")
	})
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		resume := sealDeleteRow(t, e, e.c, 3)
		// A key change that did not carry the state over: a key mismatch.
		c := e.restart()
		c.SetAuditCheckpointKey(aktNewKey, "v2")
		sealRefused(t, c, sealReq(resume), "key mismatch")
	})
}

// (6) The seal survives rotate-kek / migrate-provider: the transition record
// names it, completion re-signs it under the new key first.
func TestAuditSeal_SurvivesKeyChange(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		c, _ := sealedEnv(t, e)
		assertSealed(t, e, c, 1)
		require.NoError(t, c.PrepareAuditKeyTransition(context.Background(), aktNewKey, "v2"))
		recs, err := parseAuditKeyTransitions(aktTransitionsValue(t, e.db))
		require.NoError(t, err)
		assert.Equal(t, auditDigest(sealsValue(t, e.db)), recs[len(recs)-1].Seals, "the transition record names the seal row")
		c2 := aktOnKey(t, e, aktNewKey, "v2", true)
		assertSealed(t, e, c2, 1)
		seals, err := parseAuditSeals(sealsValue(t, e.db))
		require.NoError(t, err)
		assert.Equal(t, "v2", seals[0].kid, "re-signed under the new key")
		assert.Zero(t, countEvents(t, e.db, fcDiscontinuityEvent))
	})
}

// (7) A checkpoint written after a seal is bound to it: it does not
// authenticate under the v1 form or another seal list.
func TestAuditSeal_CheckpointBoundToSeal(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		c, _ := sealedEnv(t, e)
		assertSealed(t, e, c, 1)
		cp, err := c.storage.LatestAuditCheckpoint(ctx)
		require.NoError(t, err)
		assert.True(t, c.checkpointSignatureValid(cp))
		assert.NotEqual(t, cp.Signature, c.signCheckpointUnder(cp, auditSealBinding{}), "not valid in the v1 form")
		assert.NotEqual(t, cp.Signature, c.signCheckpointUnder(cp, auditSealBinding{N: 1, Digest: strings.Repeat("0", 64)}), "not valid under another seal")
		hw, ok, err := c.storage.GetSystemMetadata(ctx, auditHighWaterKey)
		require.NoError(t, err)
		require.True(t, ok)
		assert.True(t, strings.HasPrefix(hw, "v2"+auditHighWaterSep+"1"+auditHighWaterSep), "the sealed high-water mark carries the binding")
	})
}

// An acceptance that stopped after writing the record (no event yet) reads
// broken until a re-run completes it.
func TestAuditSeal_IncompleteAcceptanceResumed(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		resume := sealDeleteRow(t, e, e.c, 3)
		plan, err := e.c.PlanAuditLossAcceptance(ctx, sealReq(resume))
		require.NoError(t, err)
		// Step 1 only, as a crash right after it leaves it.
		r := plan.seal
		r.payload, err = json.Marshal(r)
		require.NoError(t, err)
		r.kid = e.c.auditCkptKeyVersion
		r.mac = auditSealMAC(e.c.auditCkptKey, r.kid, r.payload)
		require.NoError(t, e.c.storage.SetSystemMetadata(ctx, auditSealsKey, encodeAuditSeals([]*auditSeal{r})))

		c := e.restart()
		assertBroken(t, e, c)
		again, err := c.PlanAuditLossAcceptance(ctx, sealReq())
		require.NoError(t, err)
		assert.True(t, again.Resume)
		_, err = c.AcceptAuditLoss(ctx, again)
		require.NoError(t, err)
		assertSealed(t, e, e.restart(), 1)
	})
}

// A tail truncation the checkpoint proves (the walk itself is clean) is
// accepted at the missing certified head.
func TestAuditSeal_TruncationAccepted(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		cp, err := e.c.storage.LatestAuditCheckpoint(ctx)
		require.NoError(t, err)
		require.NoError(t, e.db.Exec("DELETE FROM audit_events WHERE id >= ?", cp.HeadID-1).Error)
		c := e.restart()
		assertBroken(t, e, c)
		sealRefused(t, c, sealReq(cp.HeadID-1), "not the head")
		plan, err := c.PlanAuditLossAcceptance(ctx, sealReq(cp.HeadID))
		require.NoError(t, err)
		require.NotNil(t, plan.Truncation)
		assert.Equal(t, cp.HeadID, plan.Truncation.CertifiedHeadID)
		assert.Positive(t, plan.LostEvents)
		_, err = c.AcceptAuditLoss(ctx, plan)
		require.NoError(t, err)
		assertSealed(t, e, e.restart(), 1)
	})
}

// Two gaps accepted in one run: one record, one event.
func TestAuditSeal_TwoGapsOneAcceptance(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		fcCertify(t, e)
		first := sealDeleteRow(t, e, e.c, 3)
		require.NoError(t, e.db.Exec("DELETE FROM audit_events WHERE id = 7").Error)
		sealRefused(t, e.c, sealReq(first), "still breaks at audit event #8")
		sealAccept(t, e.c, sealReq(first, 8))
		assertSealed(t, e, e.restart(), 1)
	})
}

// The optional anchor binding: an export-checkpoint file taken after the lost
// rows existed measures the loss; one exported before them is refused.
func TestAuditSeal_AnchorBinding(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		fcCertify(t, e)
		cp, err := e.c.storage.LatestAuditCheckpoint(ctx)
		require.NoError(t, err)
		anchor := &AuditLossAnchor{Digest: strings.Repeat("ab", 32), ChainedEvents: cp.ChainedEvents, HeadID: cp.HeadID,
			HeadHash: cp.HeadHash, KeyVersion: cp.KeyVersion, Signature: cp.Signature}
		resume := sealDeleteRow(t, e, e.c, 3)

		early := *anchor
		early.HeadID, early.ChainedEvents = 2, 2
		early.HeadHash, _, err = e.c.storage.AuditEntryHashByID(ctx, 2)
		require.NoError(t, err)
		early.Signature = e.c.signCheckpointUnder(&models.AuditCheckpoint{ChainedEvents: 2, HeadID: 2, HeadHash: early.HeadHash, KeyVersion: early.KeyVersion}, auditSealBinding{})
		req := sealReq(resume)
		req.Anchor = &early
		sealRefused(t, e.c, req, "does not cover the lost range")

		forged := *anchor
		forged.Signature = strings.Repeat("0", 64)
		req.Anchor = &forged
		sealRefused(t, e.c, req, "does not authenticate")

		req.Anchor = anchor
		plan, err := e.c.PlanAuditLossAcceptance(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, plan.Anchor)
		assert.True(t, plan.Anchor.Verified)
		assert.Equal(t, int64(1), plan.LostEvents)
		_, err = e.c.AcceptAuditLoss(ctx, plan)
		require.NoError(t, err)
		assertSealed(t, e, e.restart(), 1)
	})
}

// (1) The compliance posture shows a sealed chain as sealed and not verified,
// with the seal as the reason.
func TestAuditSeal_PostureShowsSealed(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		c, _ := sealedEnv(t, e)
		assertSealed(t, e, c, 1)
		r, err := c.AuditVerificationStatus(context.Background())
		require.NoError(t, err)
		p := &CompliancePosture{}
		applyAuditIntegrityPosture(p, &complianceSnapshot{auditChain: r})
		assert.Equal(t, AuditVerifyStatusSealed, p.AuditIntegrity.VerificationStatus)
		assert.False(t, p.AuditIntegrity.ChainVerified, "never green")
		assert.Contains(t, p.AuditIntegrity.Reason, "seal #1")
	})
}

// (5) Deleting the seal record does not drop the floor the signed state pins:
// the lenient re-baseline path (a relabelled checkpoint key version) is still
// checked against it.
func TestAuditSeal_DeletedSealKeepsStatePin(t *testing.T) {
	fcRun(t, func(t *testing.T, e *fcEnv) {
		ctx := context.Background()
		c, _ := sealedEnv(t, e)
		assertSealed(t, e, c, 1)
		pin, err := c.signedAuditVerifyPin(ctx)
		require.NoError(t, err)
		require.NotNil(t, pin)
		require.NoError(t, e.db.Where(&models.SystemMetadata{Key: auditSealsKey}).Delete(&models.SystemMetadata{}).Error)
		c2 := e.restart()
		after, err := c2.signedAuditVerifyPin(ctx)
		require.NoError(t, err)
		require.NotNil(t, after, "the pin survives a deleted seal record")
		assert.Equal(t, pin.Events, after.Events)
		reason, tampered, err := c2.auditVerifyStateTruncation(ctx, pin.Events-1)
		require.NoError(t, err)
		assert.True(t, tampered, "a re-baseline below the pin is refused: %s", reason)
	})
}

// An acceptance stopped after any of its writes reads broken (a server started
// in between included) until a re-run completes it.
func TestAuditSeal_CrashAtEveryStepResumes(t *testing.T) {
	for _, step := range []string{"record", "event", "checkpoint", "high-water"} {
		t.Run(step, func(t *testing.T) {
			t.Parallel()
			fcRun(t, func(t *testing.T, e *fcEnv) {
				ctx := context.Background()
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

				c := e.restart()
				if step == "high-water" {
					// Record, event, checkpoint and mark are complete (the walk
					// reads sealed); the state is behind and reads broken.
					assert.Equal(t, AuditVerifyStatusBroken, incrVerify(t, c).Status)
				} else {
					assertBroken(t, e, c)
				}
				fcTick(t, e, c) // a server ran before the operator re-ran the command
				assert.NotEqual(t, AuditVerifyStatusSealed, incrVerify(t, c).Status)

				again, err := e.restart().PlanAuditLossAcceptance(ctx, sealReq())
				require.NoError(t, err, "a re-run resumes")
				assert.True(t, again.Resume)
				c2 := e.restart()
				again, err = c2.PlanAuditLossAcceptance(ctx, sealReq())
				require.NoError(t, err)
				_, err = c2.AcceptAuditLoss(ctx, again)
				require.NoError(t, err)
				assertSealed(t, e, e.restart(), 1)
			})
		})
	}
}

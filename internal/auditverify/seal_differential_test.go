package auditverify_test

// Online and offline verifiers over databases with an accepted audit loss
// (`admin audit accept-loss`, internal/core/audit_seal.go; constraint 8 of
// docs/design/recovery-options.md §2). Every fixture is sealed by the real
// internal/core code path, then tampered with; both verifiers must agree:
// SEALED (online: Valid with Seals > 0, never a valid status) for an intact
// seal, BROKEN for every tamper.

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const sealDiffEvidence = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// sealed builds a checkpointed 12-row chain, deletes rows, and accepts the
// loss at the ids the walk breaks at (or at the named ids for a truncation).
func sealed(t *testing.T, del string, ids ...uint) *diffFixture {
	t.Helper()
	f := newDiffFixture(t)
	f.logEvents(12, time.Hour)
	_, _, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	f.exec("DELETE FROM audit_events WHERE " + del)
	if len(ids) == 0 {
		v := f.oracle()
		require.False(t, v.Valid)
		ids = []uint{*v.FirstBrokenID}
	}
	plan, err := f.core.PlanAuditLossAcceptance(f.ctx, core.AuditLossRequest{BrokenIDs: ids, Operator: "ops", OSUser: "keyorix",
		Reason: "INC-7", Evidence: sealDiffEvidence})
	require.NoError(t, err)
	_, err = f.core.AcceptAuditLoss(f.ctx, plan)
	require.NoError(t, err)
	return f
}

// agree asserts the online and offline verdicts match want.
func (f *diffFixture) agree(want auditverify.Verdict) *auditverify.Result {
	f.t.Helper()
	c := core.NewKeyorixCore(f.local)
	c.SetAuditCheckpointKey(fixedCheckpointKey, "v1")
	v, err := c.VerifyAuditChain(f.ctx)
	require.NoError(f.t, err)
	r := f.verifyWith(fixedCheckpointKey)
	assert.Equal(f.t, want, r.Verdict, "offline: %s", r.Reason)
	switch want {
	case auditverify.VerdictSealed:
		assert.True(f.t, v.Valid, "online walk: %s", v.Reason)
		assert.Positive(f.t, v.Seals, "online reports the seal")
		assert.Equal(f.t, 4, r.ExitCode())
	case auditverify.VerdictBroken:
		assert.False(f.t, v.Valid, "online must read broken too")
		assert.Equal(f.t, 1, r.ExitCode())
	}
	return r
}

func (f *diffFixture) sealsValue() string {
	f.t.Helper()
	var row models.SystemMetadata
	require.NoError(f.t, f.db.Where(&models.SystemMetadata{Key: "audit_seals"}).First(&row).Error)
	return row.Value
}

// rewriteSealPayload edits the first record's JSON without re-signing it.
func (f *diffFixture) rewriteSealPayload(from, to string) {
	f.t.Helper()
	parts := strings.Split(f.sealsValue(), "\x1f")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(f.t, err)
	require.Contains(f.t, string(payload), from)
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(payload), from, to, 1)))
	f.exec(`UPDATE system_metadata SET value = ? WHERE key = ?`, strings.Join(parts, "\x1f"), "audit_seals")
}

func TestSealDifferential_GapSealed(t *testing.T) {
	t.Parallel()
	f := sealed(t, "id = 4")
	r := f.agree(auditverify.VerdictSealed)
	assert.True(t, r.Seal.Present)
	assert.True(t, r.Seal.Authenticated)
	require.Len(t, r.Seal.Seals, 1)
	assert.Equal(t, "ops", r.Seal.Seals[0].Operator)
	assert.Equal(t, int64(1), r.Seal.Seals[0].LostEvents)
	assert.True(t, r.Checkpoint.Authenticated, "the re-seal checkpoint verifies under the seal binding")
	assert.Contains(t, strings.Join(r.NotProven, "\n"), "seal #1 accepted as lost")
	// More activity after the seal, and a fresh checkpoint: still sealed.
	f.logEvents(3, 0)
	_, _, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	f.agree(auditverify.VerdictSealed)
}

func TestSealDifferential_TruncationSealed(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(12, time.Hour)
	cp, _, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	f.exec("DELETE FROM audit_events WHERE id >= ?", cp.HeadID-1)
	plan, err := f.core.PlanAuditLossAcceptance(f.ctx, core.AuditLossRequest{BrokenIDs: []uint{cp.HeadID}, Operator: "ops",
		Reason: "INC-8", Evidence: sealDiffEvidence})
	require.NoError(t, err)
	_, err = f.core.AcceptAuditLoss(f.ctx, plan)
	require.NoError(t, err)
	f.agree(auditverify.VerdictSealed)
}

func TestSealDifferential_TamperReadsBrokenBoth(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		tamper func(f *diffFixture)
	}{
		{"seal row deleted", func(f *diffFixture) { f.exec(`DELETE FROM system_metadata WHERE key = ?`, "audit_seals") }},
		{"seal record altered", func(f *diffFixture) { f.rewriteSealPayload(`"operator":"ops"`, `"operator":"mallory"`) }},
		{"seal record moved", func(f *diffFixture) { f.rewriteSealPayload(`"resume_id":5`, `"resume_id":6`) }},
		{"seal event removed", func(f *diffFixture) {
			f.exec(`DELETE FROM audit_events WHERE event_type = ?`, "system.audit_loss_accepted")
		}},
		{"row before the gap removed", func(f *diffFixture) { f.exec("DELETE FROM audit_events WHERE id = 3") }},
		{"row put back into the gap", func(f *diffFixture) {
			var row models.AuditEvent
			require.NoError(f.t, f.db.First(&row, 3).Error)
			row.ID = 4
			require.NoError(f.t, f.db.Create(&row).Error)
		}},
		{"resume row rewritten", func(f *diffFixture) {
			f.exec(`UPDATE audit_events SET description = 'tampered' WHERE id = 5`)
		}},
		{"high-water mark lowered to v1", func(f *diffFixture) {
			var row models.SystemMetadata
			require.NoError(f.t, f.db.Where(&models.SystemMetadata{Key: "audit_checkpoint_highwater"}).First(&row).Error)
			cp, sig, ok := auditverify.ParseHighWater(row.Value)
			require.True(f.t, ok)
			require.Equal(f.t, 1, cp.Seals, "the sealed mark carries the binding")
			cp.Seals, cp.SealDigest = 0, ""
			f.exec(`UPDATE system_metadata SET value = ? WHERE key = ?`, auditverify.EncodeHighWater(cp, sig), "audit_checkpoint_highwater")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := sealed(t, "id = 4")
			f.agree(auditverify.VerdictSealed)
			tc.tamper(f)
			f.agree(auditverify.VerdictBroken)
		})
	}
}

// A replayed, shorter seal list (the second acceptance dropped) is BROKEN.
func TestSealDifferential_ReplayedSealListBroken(t *testing.T) {
	t.Parallel()
	f := sealed(t, "id = 4")
	one := f.sealsValue()
	f.logEvents(4, 0)
	f.exec("DELETE FROM audit_events WHERE id = 15")
	v := f.oracle()
	require.False(t, v.Valid)
	plan, err := f.core.PlanAuditLossAcceptance(f.ctx, core.AuditLossRequest{BrokenIDs: []uint{*v.FirstBrokenID}, Operator: "ops",
		Reason: "INC-9", Evidence: sealDiffEvidence})
	require.NoError(t, err)
	_, err = f.core.AcceptAuditLoss(f.ctx, plan)
	require.NoError(t, err)
	r := f.agree(auditverify.VerdictSealed)
	assert.Len(t, r.Seal.Seals, 2)
	f.exec(`UPDATE system_metadata SET value = ? WHERE key = ?`, one, "audit_seals")
	f.agree(auditverify.VerdictBroken)
}

// Without the checkpoint key the seal cannot be authenticated: fail closed.
func TestSealDifferential_NoKeyFailsClosed(t *testing.T) {
	t.Parallel()
	f := sealed(t, "id = 4")
	r, err := auditverify.Verify(f.ctx, f.openIndependent(), auditverify.Options{})
	require.NoError(t, err)
	assert.Equal(t, auditverify.VerdictBroken, r.Verdict)
	assert.Contains(t, r.Reason, "cannot be authenticated")
	assert.False(t, r.Seal.Authenticated)
}

// The seal survives a key change (rotate-kek / migrate-provider).
func TestSealDifferential_SurvivesKeyChange(t *testing.T) {
	t.Parallel()
	f := sealed(t, "id = 4")
	require.NoError(t, f.core.PrepareAuditKeyTransition(f.ctx, ktKey2, "v2"))
	c2 := core.NewKeyorixCore(f.local)
	c2.SetAuditCheckpointKey(ktKey2, "v2")
	_, err := c2.CompleteAuditKeyTransition(f.ctx)
	require.NoError(t, err)
	v, err := c2.VerifyAuditChain(f.ctx)
	require.NoError(t, err)
	assert.True(t, v.Valid, v.Reason)
	assert.Equal(t, 1, v.Seals)
	r := f.verifyWith(ktKey2)
	assert.Equal(t, auditverify.VerdictSealed, r.Verdict, r.Reason)
	recs, err := auditverify.ParseSeals(f.sealsValue())
	require.NoError(t, err)
	assert.True(t, recs[0].MACValid(ktKey2), "re-signed under the new key")
	assert.Equal(t, "v2", recs[0].KeyVersion())
}

// An external anchor exported before the loss still cross-checks after the
// seal (it is bound to the pre-seal form); one exported after it too.
func TestSealDifferential_PreAndPostSealAnchors(t *testing.T) {
	t.Parallel()
	f := newDiffFixture(t)
	f.logEvents(12, time.Hour)
	cp, _, err := f.core.WriteAuditCheckpoint(f.ctx)
	require.NoError(t, err)
	pre := &auditverify.ExternalAnchorBundle{ChainedEvents: cp.ChainedEvents, HeadID: uint64(cp.HeadID), HeadHash: cp.HeadHash, KeyVersion: cp.KeyVersion, Signature: cp.Signature}
	f.exec("DELETE FROM audit_events WHERE id = 4")
	plan, err := f.core.PlanAuditLossAcceptance(f.ctx, core.AuditLossRequest{BrokenIDs: []uint{5}, Operator: "ops", Reason: "INC-10",
		Evidence: sealDiffEvidence, Anchor: &core.AuditLossAnchor{Digest: strings.Repeat("cd", 32), ChainedEvents: cp.ChainedEvents,
			HeadID: cp.HeadID, HeadHash: cp.HeadHash, KeyVersion: cp.KeyVersion, Signature: cp.Signature}})
	require.NoError(t, err)
	res, err := f.core.AcceptAuditLoss(f.ctx, plan)
	require.NoError(t, err)

	r, err := auditverify.Verify(f.ctx, f.openIndependent(), auditverify.Options{CheckpointKey: fixedCheckpointKey, ExternalAnchor: pre})
	require.NoError(t, err)
	assert.Equal(t, auditverify.VerdictSealed, r.Verdict, r.Reason)
	assert.True(t, r.ExternalAnchor.Authenticated, "the pre-seal anchor authenticates under the binding it was exported with")

	post := &auditverify.ExternalAnchorBundle{ChainedEvents: res.Checkpoint.ChainedEvents, HeadID: uint64(res.Checkpoint.HeadID),
		HeadHash: res.Checkpoint.HeadHash, KeyVersion: res.Checkpoint.KeyVersion, Signature: res.Checkpoint.Signature}
	r, err = auditverify.Verify(f.ctx, f.openIndependent(), auditverify.Options{CheckpointKey: fixedCheckpointKey, ExternalAnchor: post})
	require.NoError(t, err)
	assert.Equal(t, auditverify.VerdictSealed, r.Verdict, r.Reason)
	assert.True(t, r.ExternalAnchor.Authenticated)

	// A key holder's pre-seal anchor certifying more history than the seal
	// accepted a loss against: rows were lost beyond the accepted ones.
	more := *pre
	more.ChainedEvents += 5
	more.Signature = auditverify.SignCheckpoint(&auditverify.Checkpoint{ChainedEvents: more.ChainedEvents, HeadID: more.HeadID,
		HeadHash: more.HeadHash, KeyVersion: more.KeyVersion}, fixedCheckpointKey)
	r, err = auditverify.Verify(f.ctx, f.openIndependent(), auditverify.Options{CheckpointKey: fixedCheckpointKey, ExternalAnchor: &more})
	require.NoError(t, err)
	assert.Equal(t, auditverify.VerdictBroken, r.Verdict, r.Reason)
	assert.Contains(t, r.Reason, "beyond the accepted ones")
}

// The core writes exactly what the independent parser reads.
func TestSealDifferential_FormatMatchesCore(t *testing.T) {
	t.Parallel()
	f := sealed(t, "id = 4")
	recs, err := auditverify.ParseSeals(f.sealsValue())
	require.NoError(t, err)
	require.Len(t, recs, 1)
	s := recs[0]
	assert.Equal(t, 1, s.Seq)
	assert.True(t, s.MACValid(fixedCheckpointKey))
	assert.False(t, s.MACValid(ktKey2))
	require.Len(t, s.Gaps, 1)
	assert.Equal(t, uint64(3), s.Gaps[0].LastGoodID)
	assert.Equal(t, uint64(5), s.Gaps[0].ResumeID)
	raw, err := json.Marshal(s)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"evidence":"`+sealDiffEvidence+`"`)
}

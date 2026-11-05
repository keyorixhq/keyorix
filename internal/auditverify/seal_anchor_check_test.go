package auditverify_test

// AUDIT-VERIFY-ONLINE-1 item 3: `admin audit accept-loss --anchor-sha256`
// records only the digest of an anchor file kept elsewhere, and nothing ever
// compared that file with the digest. verify-audit now checks a supplied
// --anchor against the digest each seal records (and against the coverage
// rule accept-loss applies to --anchor), and reports the rows a seal recorded
// as unpinned. Both are reported, never a verdict change: what stays
// unchecked is listed in what the run does not prove.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// sealAnchorEnv is what the check needs from the SQLite and PostgreSQL fixtures.
type sealAnchorEnv struct {
	t         *testing.T
	ctx       context.Context
	core      *core.KeyorixCore
	logEvents func(n int)
	exec      func(q string, args ...any)
	open      func() *auditverify.DB
}

func sealAnchorEnvSQLite(t *testing.T) sealAnchorEnv {
	f := newDiffFixture(t)
	return sealAnchorEnv{t: t, ctx: f.ctx, core: f.core, logEvents: func(n int) { f.logEvents(n, time.Hour) },
		exec: func(q string, args ...any) { f.exec(q, args...) }, open: f.openIndependent}
}

func sealAnchorEnvPostgres(t *testing.T) sealAnchorEnv {
	f := newPGFixture(t)
	return sealAnchorEnv{t: t, ctx: f.ctx, core: f.core, logEvents: func(n int) { f.logEvents(n, time.Hour) },
		exec: func(q string, args ...any) { require.NoError(t, f.db.Exec(q, args...).Error) }, open: f.openIndependent}
}

// anchorFile is an export-checkpoint style file for cp and its SHA-256.
func anchorFile(t *testing.T, cp *models.AuditCheckpoint) (*auditverify.ExternalAnchorBundle, string) {
	t.Helper()
	b := &auditverify.ExternalAnchorBundle{ChainedEvents: cp.ChainedEvents, HeadID: uint64(cp.HeadID), HeadHash: cp.HeadHash,
		KeyVersion: cp.KeyVersion, Signature: cp.Signature}
	raw, err := json.Marshal(b)
	require.NoError(t, err)
	sum := sha256.Sum256(raw)
	return b, hex.EncodeToString(sum[:])
}

func (e sealAnchorEnv) verify(o auditverify.Options) (*auditverify.Result, auditverify.SealSummary) {
	e.t.Helper()
	o.CheckpointKey = fixedCheckpointKey
	r, err := auditverify.Verify(e.ctx, e.open(), o)
	require.NoError(e.t, err)
	require.Equal(e.t, auditverify.VerdictSealed, r.Verdict, r.Reason)
	require.Len(e.t, r.Seal.Seals, 1)
	return r, r.Seal.Seals[0]
}

// sealWith deletes row 4 and accepts the loss with req's anchor fields (the
// caller logged and checkpointed the chain).
func (e sealAnchorEnv) sealWith(req core.AuditLossRequest) {
	e.t.Helper()
	e.exec("DELETE FROM audit_events WHERE id = 4")
	req.BrokenIDs, req.Operator, req.OSUser, req.Reason, req.Evidence = []uint{5}, "ops", "keyorix", "INC-11", sealDiffEvidence
	plan, err := e.core.PlanAuditLossAcceptance(e.ctx, req)
	require.NoError(e.t, err)
	_, err = e.core.AcceptAuditLoss(e.ctx, plan)
	require.NoError(e.t, err)
}

func runSealAnchorDigestOnly(t *testing.T, e sealAnchorEnv) {
	e.logEvents(12)
	cp, _, err := e.core.WriteAuditCheckpoint(e.ctx)
	require.NoError(t, err)
	bundle, digest := anchorFile(t, cp)
	e.sealWith(core.AuditLossRequest{AnchorDigest: digest})

	r, s := e.verify(auditverify.Options{})
	require.NotNil(t, s.Anchor, "the seal names the anchor it recorded")
	assert.Equal(t, digest, s.Anchor.Digest)
	assert.False(t, s.Anchor.VerifiedAtAcceptance)
	assert.Equal(t, auditverify.SealAnchorNotSupplied, s.Anchor.Check)
	assert.Equal(t, []auditverify.SealSpan{{FromID: 1, ThroughID: 3}}, s.Unpinned, "rows 1-3 were pinned by nothing signed")
	notProven := strings.Join(r.NotProven, "\n")
	assert.Contains(t, notProven, "seal #1 recorded by digest only (sha256 "+digest+")")
	assert.Contains(t, notProven, "audit events #1 through #3 were not rewritten before seal #1")

	r, s = e.verify(auditverify.Options{ExternalAnchor: bundle, ExternalAnchorSHA256: strings.ToUpper(digest)})
	assert.Equal(t, auditverify.SealAnchorMatches, s.Anchor.Check, s.Anchor.Detail)
	assert.Equal(t, digest, r.ExternalAnchor.SHA256)
	assert.NotContains(t, strings.Join(r.NotProven, "\n"), "recorded by digest only", "a confirmed anchor is proven")

	_, s = e.verify(auditverify.Options{ExternalAnchor: bundle, ExternalAnchorSHA256: strings.Repeat("ab", 32)})
	assert.Equal(t, auditverify.SealAnchorDiffers, s.Anchor.Check)
	assert.Contains(t, s.Anchor.Detail, strings.Repeat("ab", 32))

	forged := *bundle
	forged.Signature = strings.Repeat("00", 32)
	r, s = e.verify(auditverify.Options{ExternalAnchor: &forged, ExternalAnchorSHA256: digest})
	assert.Equal(t, auditverify.SealAnchorUnauthenticated, s.Anchor.Check, "the same digest does not make an unsigned file evidence")
	assert.Contains(t, strings.Join(r.NotProven, "\n"), "recorded by digest only")
}

func TestSealAnchorCheck_DigestOnly(t *testing.T) {
	t.Parallel()
	runSealAnchorDigestOnly(t, sealAnchorEnvSQLite(t))
}

func TestSealAnchorCheck_DigestOnly_Postgres(t *testing.T) {
	t.Parallel()
	runSealAnchorDigestOnly(t, sealAnchorEnvPostgres(t))
}

// The recorded file was exported before the lost rows existed: it matches,
// authenticates, and still is no evidence for this loss.
func TestSealAnchorCheck_AnchorBeforeTheLossDoesNotCover(t *testing.T) {
	t.Parallel()
	e := sealAnchorEnvSQLite(t)
	e.logEvents(3)
	early, _, err := e.core.WriteAuditCheckpoint(e.ctx)
	require.NoError(t, err)
	e.logEvents(9)
	_, _, err = e.core.WriteAuditCheckpoint(e.ctx)
	require.NoError(t, err)
	bundle, digest := anchorFile(t, early)
	e.sealWith(core.AuditLossRequest{AnchorDigest: digest})

	r, s := e.verify(auditverify.Options{ExternalAnchor: bundle, ExternalAnchorSHA256: digest})
	assert.True(t, r.ExternalAnchor.Authenticated)
	assert.Equal(t, auditverify.SealAnchorNotCovering, s.Anchor.Check)
	assert.Contains(t, s.Anchor.Detail, "through #3 only")
	assert.Contains(t, strings.Join(r.NotProven, "\n"), "recorded by digest only")
}

// A file passed with --anchor at acceptance is reported as verified then, and
// a re-supplied copy matches.
func TestSealAnchorCheck_VerifiedAtAcceptance(t *testing.T) {
	t.Parallel()
	e := sealAnchorEnvSQLite(t)
	e.logEvents(12)
	cp, _, err := e.core.WriteAuditCheckpoint(e.ctx)
	require.NoError(t, err)
	bundle, digest := anchorFile(t, cp)
	e.sealWith(core.AuditLossRequest{Anchor: &core.AuditLossAnchor{Digest: digest, ChainedEvents: cp.ChainedEvents,
		HeadID: cp.HeadID, HeadHash: cp.HeadHash, KeyVersion: cp.KeyVersion, Signature: cp.Signature}})

	r, s := e.verify(auditverify.Options{})
	assert.True(t, s.Anchor.VerifiedAtAcceptance)
	assert.Equal(t, auditverify.SealAnchorNotSupplied, s.Anchor.Check)
	assert.NotContains(t, strings.Join(r.NotProven, "\n"), "recorded by digest only", "it was checked at acceptance")

	_, s = e.verify(auditverify.Options{ExternalAnchor: bundle, ExternalAnchorSHA256: digest})
	assert.Equal(t, auditverify.SealAnchorMatches, s.Anchor.Check)
}

// A seal without an anchor reports none.
func TestSealAnchorCheck_NoAnchorRecorded(t *testing.T) {
	t.Parallel()
	f := sealed(t, "id = 4")
	r := f.agree(auditverify.VerdictSealed)
	require.Len(t, r.Seal.Seals, 1)
	assert.Nil(t, r.Seal.Seals[0].Anchor)
}

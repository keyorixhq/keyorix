// audit_seal_accept.go — `keyorix-server admin audit accept-loss`: verify that
// a loss of audit rows is genuine and proven, then seal it (audit_seal.go).
//
// The command runs offline (server stopped, exclusive admin lock) with the
// master passphrase, so the checkpoint key, not a database writer or an API
// token, is the authority. PlanAuditLossAcceptance only reads: it walks the
// chain and refuses everything that is not a proven loss at exactly the ids the
// operator named (constraint 3). AcceptAuditLoss writes, in an order where a
// crash at any point reads broken and a re-run finishes the job:
//
//  1. the seal record (audit_seals; nothing authenticates against it yet, and
//     a record without its event reads broken);
//  2. the in-chain system.audit_loss_accepted event, the one audit event;
//  3. a fresh checkpoint and high-water mark of what survives, bound to the
//     seal (the re-seal; the mark is lowered to it);
//  4. the verification state, with what was accepted moved to its accepted
//     list, the pin reset to the new checkpoint and no full verification yet.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ErrAuditLossRefused is returned when accept-loss refuses to seal.
var ErrAuditLossRefused = errors.New("audit loss not accepted")

func auditLossRefused(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrAuditLossRefused, fmt.Sprintf(format, args...))
}

// AuditLossAnchor is an export-checkpoint file the acceptance is bound to,
// already parsed by the command (internal/core cannot import auditverify).
type AuditLossAnchor struct {
	Digest        string
	ChainedEvents int64
	HeadID        uint
	HeadHash      string
	KeyVersion    string
	Signature     string
}

// AuditLossRequest is what the operator gives accept-loss.
type AuditLossRequest struct {
	// BrokenIDs are the ids the operator names: the first row after each gap
	// (where the walk breaks), or the missing certified head of a truncation.
	BrokenIDs []uint
	Operator  string
	OSUser    string
	Reason    string
	// Evidence is the hex SHA-256 of the evidence the operator kept.
	Evidence string
	// Anchor (a verified file) or AnchorDigest (a digest only, recorded).
	Anchor       *AuditLossAnchor
	AnchorDigest string
	// ResumeSeal is the digest of the unfinished seal record the operator
	// read in the plan (--resume-seal): without it a resume writes nothing
	// (#3803), so a habitual re-run with --confirm cannot complete a record
	// the operator never looked at.
	ResumeSeal string
}

// Limits on the operator name and reason, which the seal stores in its record
// and in the in-chain event description.
const (
	AuditLossOperatorMaxLen = 256
	AuditLossReasonMaxLen   = 1024
)

// AuditLossTextProblem says why an operator name or reason cannot be stored
// ("" when both can): invalid UTF-8, a control or format character or a line
// or paragraph separator (a newline, U+2028, a terminal escape or a bidi
// override would forge or hide lines wherever the event description is
// shown), or more bytes than its limit.
func AuditLossTextProblem(operator, reason string) string {
	for _, f := range []struct {
		name, val string
		max       int
	}{{"--operator", operator, AuditLossOperatorMaxLen}, {"--reason", reason, AuditLossReasonMaxLen}} {
		switch {
		case !utf8.ValidString(f.val):
			return f.name + " is not valid UTF-8"
		case strings.ContainsFunc(f.val, func(r rune) bool { return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) }):
			return f.name + " contains a control or format character or a line separator (newlines and escape sequences are not stored)"
		case len(f.val) > f.max:
			return fmt.Sprintf("%s is longer than %d bytes", f.name, f.max)
		}
	}
	return ""
}

// AuditLossPlan is what accept-loss will write, for the operator to confirm.
type AuditLossPlan struct {
	Seq        int
	Gaps       []AuditSealGap
	Truncation *AuditSealTruncation
	Before     *AuditSealCount
	After      AuditSealCount
	LostEvents int64
	Anchor     *AuditSealAnchor
	Accepted   []AuditSealAccepted
	// Witness is the host's high-water witness file (SQLite installs) when it
	// authenticates under the seal list before this acceptance; it counts in
	// Before, and the re-seal lowers it to After. WitnessNote says why a
	// witness that is present is not counted (it is replaced all the same).
	Witness     *AuditSealCount
	WitnessNote string
	// Unpinned are the surviving rows before each break that no signed
	// artifact pins: a rewrite of them before this acceptance cannot be
	// excluded (#3802). The seal records them.
	Unpinned []AuditSealSpan
	// Resume: an earlier acceptance stopped before it finished; this run
	// completes it and writes no new record, and only when the request named
	// ResumeDigest, the digest of that record (resumeNamed).
	Resume       bool
	ResumeDigest string

	seal        *auditSeal
	resumeNamed bool
}

// Describe is the human summary the command prints before confirming.
func (p *AuditLossPlan) Describe() []string {
	var out []string
	if p.Resume {
		out = append(out, fmt.Sprintf("Seal #%d was recorded but its acceptance did not finish; this run completes it (no new record).", p.Seq),
			fmt.Sprintf("  recorded %s by %q (host user %q), reason %q", p.seal.At.UTC().Format(time.RFC3339), p.seal.Operator, p.seal.OSUser, p.seal.Reason),
			"  If you did not start this acceptance, do not confirm: a resume you did not start is a rollback of the database until proven otherwise (compare the trail with an external anchor first).",
			fmt.Sprintf("  record digest %s: completing it requires --resume-seal %s (nothing is written without it, even with --confirm)", p.ResumeDigest, p.ResumeDigest))
	}
	out = append(out, fmt.Sprintf("Seal #%d accepts %s.", p.Seq, p.seal.lostRange()))
	for _, g := range p.Gaps {
		out = append(out, fmt.Sprintf("  gap: rows after #%d (hash %s) up to #%d are gone; #%d resumes the chain (hash %s)",
			g.LastGoodID, shortHash(g.LastGoodHash), g.ResumeID, g.ResumeID, shortHash(g.ResumeHash)))
	}
	if t := p.Truncation; t != nil {
		out = append(out, fmt.Sprintf("  truncation: certified head #%d (hash %s) is gone; the chain ends on #%d",
			t.CertifiedHeadID, shortHash(t.CertifiedHeadHash), t.SurvivingHeadID))
	}
	if b := p.Before; b != nil {
		out = append(out, fmt.Sprintf("  certified before the loss: %d events through #%d (%s)", b.Events, b.HeadID, b.Source))
	} else {
		out = append(out, "  certified before the loss: nothing authenticated covers the lost rows (the loss is unmeasured)")
	}
	out = append(out, fmt.Sprintf("  surviving: %d events through #%d; a new checkpoint and high-water mark are signed for them", p.After.Events, p.After.HeadID))
	if w := p.Witness; w != nil && w.Events > p.After.Events {
		out = append(out, fmt.Sprintf("  host witness file: certifies %d events through #%d (hash %s); confirming LOWERS it to the surviving %d events through #%d",
			w.Events, w.HeadID, shortHash(w.HeadHash), p.After.Events, p.After.HeadID))
	}
	if p.WitnessNote != "" {
		out = append(out, "  host witness file: "+p.WitnessNote)
	}
	for _, s := range p.Unpinned {
		out = append(out, fmt.Sprintf("  unauthenticated: audit events #%d through #%d are pinned by no signed checkpoint, mark, anchor or state; a rewrite of them before this acceptance cannot be excluded (the seal records it)", s.FromID, s.ThroughID))
	}
	if a := p.Anchor; a != nil {
		if a.Verified {
			out = append(out, fmt.Sprintf("  external anchor %s: authenticated, %d events through #%d", a.Digest, a.ChainedEvents, a.HeadID))
		} else {
			out = append(out, fmt.Sprintf("  external anchor digest %s: recorded only (the file was not supplied, so it was not checked)", a.Digest))
		}
	}
	for _, a := range p.Accepted {
		out = append(out, fmt.Sprintf("  clears %s: %s", a.What, a.Reason))
	}
	out = append(out, "After this the status is not_proven until a full verification completes, then sealed: never valid again.")
	return out
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// auditLossFindings are the facts both plan and resume need.
type auditLossFindings struct {
	seals  *auditSealSet
	anchor *storage.AuditChainAnchor
	state  *auditVerifyState
	resume bool
}

// PlanAuditLossAcceptance verifies first and returns what accept-loss would
// write, or ErrAuditLossRefused when the loss is not genuine and proven at
// exactly req.BrokenIDs. It never writes.
func (c *KeyorixCore) PlanAuditLossAcceptance(ctx context.Context, req AuditLossRequest) (*AuditLossPlan, error) {
	if !c.AuditCheckpointsAvailable() {
		return nil, auditLossRefused("no checkpoint signing key: storage.encryption must be enabled and the master key available")
	}
	if strings.TrimSpace(req.Operator) == "" || strings.TrimSpace(req.Reason) == "" || req.Evidence == "" {
		return nil, auditLossRefused("an operator name, a reason and an evidence digest are required")
	}
	if why := AuditLossTextProblem(strings.TrimSpace(req.Operator), strings.TrimSpace(req.Reason)); why != "" {
		return nil, auditLossRefused("%s", why)
	}
	f, err := c.auditLossPreflight(ctx)
	if err != nil {
		return nil, err
	}
	if f.resume {
		last := f.seals.recs[len(f.seals.recs)-1]
		if named := last.namedIDs(); len(req.BrokenIDs) > 0 && !sameIDs(req.BrokenIDs, named) {
			return nil, auditLossRefused("seal #%d was recorded for audit events %v but its acceptance did not finish: re-run without --first-broken-id (or with %v) to complete it, then accept a new loss", last.Seq, named, named)
		}
		digest := last.digest()
		if req.ResumeSeal != "" && !strings.EqualFold(req.ResumeSeal, digest) {
			return nil, auditLossRefused("--resume-seal %s does not name the unfinished seal #%d (record digest %s): run without --resume-seal, read the plan, then pass the digest it prints", req.ResumeSeal, last.Seq, digest)
		}
		if err := c.auditLossResumeCheck(ctx, f, last); err != nil {
			return nil, err
		}
		return &AuditLossPlan{Seq: last.Seq, Gaps: last.Gaps, Truncation: last.Truncation, Before: last.Before, After: last.After,
			LostEvents: last.LostEvents, Anchor: last.Anchor, Accepted: auditLossResumeAccepted(last, f.state), Unpinned: last.Unpinned,
			Resume: true, ResumeDigest: digest, seal: last, resumeNamed: req.ResumeSeal != ""}, nil
	}
	if req.ResumeSeal != "" {
		return nil, auditLossRefused("--resume-seal names seal record %s, but no acceptance is unfinished: there is nothing to resume (drop --resume-seal to accept a new loss)", req.ResumeSeal)
	}
	if len(req.BrokenIDs) == 0 {
		return nil, auditLossRefused("name the id where the walk breaks (--first-broken-id)")
	}
	ids := slices.Clone(req.BrokenIDs)
	slices.Sort(ids)
	if len(slices.Compact(ids)) != len(req.BrokenIDs) {
		return nil, auditLossRefused("an id is named twice")
	}

	plan := &AuditLossPlan{Seq: len(f.seals.recs) + 1, LostEvents: -1}
	gaps, rest, err := c.planAuditGaps(ctx, f, ids)
	if err != nil {
		return nil, err
	}
	plan.Gaps = gaps
	all := sealedGaps(f.seals.recs, gaps)
	full, err := c.walkAuditChainGaps(ctx, storage.AuditChainSegment{Anchor: f.anchor}, all)
	if err != nil {
		return nil, err
	}
	if !full.Valid {
		id := uint(0)
		if full.FirstBrokenID != nil {
			id = *full.FirstBrokenID
		}
		return nil, auditLossRefused("with the named gaps accepted the walk still breaks at audit event #%d (%s): name every break, or investigate it first", id, full.Reason)
	}
	purged := anchorPurgedEvents(f.anchor)
	plan.After = AuditSealCount{Events: full.ChainedEvents + purged, HeadID: full.HeadID, HeadHash: full.HeadHash, Source: "walk"}

	if plan.Witness, plan.WitnessNote, err = c.auditLossWitness(f); err != nil {
		return nil, err
	}
	before, err := c.auditLossBefore(ctx, f, plan.Witness)
	if err != nil {
		return nil, err
	}
	if req.Anchor != nil {
		a, err := c.auditLossAnchor(ctx, f, req.Anchor, gaps, plan.After)
		if err != nil {
			return nil, err
		}
		plan.Anchor = a
		if before == nil || a.ChainedEvents > before.Events {
			before = &AuditSealCount{Events: a.ChainedEvents, HeadID: a.HeadID, HeadHash: a.HeadHash, Source: "external anchor"}
		}
	} else if req.AnchorDigest != "" {
		plan.Anchor = &AuditSealAnchor{Digest: strings.ToLower(req.AnchorDigest)}
	}
	plan.Before = before

	if len(rest) > 0 {
		t, err := c.planAuditTruncation(ctx, f, gaps, rest, before, plan.After)
		if err != nil {
			return nil, err
		}
		plan.Truncation = t
	} else if len(gaps) == 0 {
		return nil, auditLossRefused("nothing to accept")
	}
	if err := c.auditLossBeforeHeadNamed(ctx, f, before, plan.Truncation); err != nil {
		return nil, err
	}
	if before != nil && before.HeadID != 0 {
		through, err := c.walkAuditChainGaps(ctx, storage.AuditChainSegment{Anchor: f.anchor, ThroughID: before.HeadID}, all)
		if err != nil {
			return nil, err
		}
		lost := before.Events - (through.ChainedEvents + purged)
		switch {
		case through.Valid && lost > 0:
			plan.LostEvents = lost
		case through.Valid && slices.ContainsFunc(gaps, func(g AuditSealGap) bool { return before.HeadID > g.LastGoodID }):
			// Signed while the rows the gap names existed, so it counted
			// them: a measured loss of 0 is a rewritten row (#3802).
			return nil, auditLossRefused("%s certifies %d events through #%d, signed after the rows before the gap, and counts every row still there (%d): nothing was lost, so the break is a rewritten row; investigate",
				before.Source, before.Events, before.HeadID, through.ChainedEvents+purged)
		}
	}
	if plan.Unpinned, err = c.auditLossCheckPins(ctx, f, plan); err != nil {
		return nil, err
	}
	plan.Accepted = auditLossAccepted(f.state, gaps, plan.Truncation)
	plan.seal = &auditSeal{V: 1, Seq: plan.Seq, At: c.now().UTC(), Operator: strings.TrimSpace(req.Operator), OSUser: req.OSUser,
		Reason: strings.TrimSpace(req.Reason), Evidence: strings.ToLower(req.Evidence), Gaps: gaps, Truncation: plan.Truncation,
		Before: plan.Before, After: plan.After, LostEvents: plan.LostEvents, Anchor: plan.Anchor, Accepted: plan.Accepted, Unpinned: plan.Unpinned}
	return plan, nil
}

// auditLossPreflight refuses everything that is not about lost rows: an
// untrusted seal record, a key mismatch, an unauthenticated store.
func (c *KeyorixCore) auditLossPreflight(ctx context.Context) (*auditLossFindings, error) {
	seals, err := c.loadAuditSeals(ctx)
	if err != nil {
		return nil, err
	}
	if seals.problem != "" && !seals.pending {
		return nil, auditLossRefused("the audit seal record cannot be trusted (%s): that is tampering with an earlier acceptance, not a row loss", seals.problem)
	}
	// An acceptance that stopped part way: its event is missing, or the
	// checkpoint, high-water mark and state were not all written yet (an
	// authentic state saved under fewer seals). A re-run completes it; the
	// half-written artifacts are not judged, they are rewritten.
	resume := seals.pending
	if !resume && len(seals.recs) > 0 {
		if resume, err = c.auditStateBehindSeals(ctx, len(seals.recs)); err != nil {
			return nil, err
		}
	}
	ev, err := c.scanAuditVerifyEvidence(ctx)
	if err != nil {
		return nil, err
	}
	if why, err := c.auditKeyTransitionProblem(ctx, nil, ev); err != nil {
		return nil, err
	} else if why != "" {
		return nil, auditLossRefused("key mismatch (%s): follow the key-rotation runbook, a key epoch problem is not a row loss", why)
	}
	cp, err := c.storage.LatestAuditCheckpoint(ctx)
	if err != nil {
		return nil, err
	}
	if cp != nil && !resume && !c.checkpointSignatureValid(cp) {
		if cp.KeyVersion != c.auditCkptKeyVersion {
			return nil, auditLossRefused("key mismatch: the latest checkpoint #%d claims key version %q, not the current %q (a key change that did not carry the state over); follow the key-rotation runbook", cp.ID, cp.KeyVersion, c.auditCkptKeyVersion)
		}
		return nil, auditLossRefused("the latest checkpoint #%d fails its signature under the current key: the checkpoint was tampered with, which is not a row loss", cp.ID)
	}
	if val, ok, err := c.storage.GetSystemMetadata(ctx, auditHighWaterKey); err != nil {
		return nil, err
	} else if ok && !resume {
		hw, sig, parsed := c.parseAuditHighWaterBound(val)
		switch {
		case !parsed:
			return nil, auditLossRefused("the audit high-water mark is malformed (an unauthenticated store)")
		case !c.checkpointSigMatches(hw, sig) && hw.KeyVersion != c.auditCkptKeyVersion:
			return nil, auditLossRefused("key mismatch: the audit high-water mark claims key version %q, not the current %q", hw.KeyVersion, c.auditCkptKeyVersion)
		case !c.checkpointSigMatches(hw, sig):
			return nil, auditLossRefused("the audit high-water mark fails its signature under the current key (tampered, not a row loss)")
		}
	} else if !ok && !resume && cp != nil {
		// Every checkpoint write advances the mark beside it, so a signed
		// checkpoint without one is a deleted mark (the tail check reads it as
		// tampering), and it would under-measure what the seal records.
		return nil, auditLossRefused("the audit high-water mark is missing although signed checkpoint #%d exists (deleted: an unauthenticated store, not a row loss)", cp.ID)
	}
	anchor, err := c.loadAuditRetentionAnchor(ctx)
	if err != nil {
		return nil, err
	}
	if _, ok, err := c.storage.GetSystemMetadata(ctx, auditRetentionAnchorKey); err != nil {
		return nil, err
	} else if ok && anchor == nil {
		return nil, auditLossRefused("the retention anchor does not authenticate under the current key (an unauthenticated store or a key mismatch)")
	}
	st, stReason, err := c.loadAuditVerifyStateUnobserved(ctx)
	if err != nil {
		return nil, err
	}
	if stReason != "" {
		return nil, auditLossRefused("the verification state is untrusted (%s): not proven, run a full verification first", stReason)
	}
	if d := st.Discontinuity; d != nil && !resume {
		switch d.Kind {
		case auditDiscDeleted, auditDiscPastHead, auditDiscBeforeBreak:
		default:
			return nil, auditLossRefused("the verification state discontinuity (%s: %s) is not a row loss: follow its runbook path", d.Kind, d.Reason)
		}
	}
	return &auditLossFindings{seals: seals, anchor: anchor, state: st, resume: resume}, nil
}

// auditStateBehindSeals reports whether the stored verification state is
// authentic and behind the n authentic seals: saved under fewer, or carrying
// the seal-record discontinuity a server started in between recorded. That is
// an acceptance stopped between its event and its state save. A missing or
// garbled state is not "behind" (a discontinuity a re-run does not rewrite).
func (c *KeyorixCore) auditStateBehindSeals(ctx context.Context, n int) (bool, error) {
	val, ok, err := c.storage.GetSystemMetadata(ctx, auditVerifyStateKey)
	if err != nil || !ok {
		return false, err
	}
	s, _, _, err := c.decodeAuditVerifyStateCarried(ctx, val)
	if err != nil || s == nil {
		return false, err
	}
	// A server started in between saves the state with the seal-record
	// discontinuity (saved before the acceptance) under the current count.
	return s.Seals < n || (s.Discontinuity != nil && s.Discontinuity.Kind == auditDiscSeal), nil
}

// auditLossResumeCheck: completing an acceptance rewrites the checkpoint and
// high-water mark from the sealed walk, so the chain must still hold at least
// what the seal recorded as surviving, with its head unchanged (nothing was
// cut since the record was written).
func (c *KeyorixCore) auditLossResumeCheck(ctx context.Context, f *auditLossFindings, last *auditSeal) error {
	v, err := c.walkAuditChainGaps(ctx, storage.AuditChainSegment{Anchor: f.anchor}, sealedGaps(f.seals.recs, nil))
	if err != nil {
		return err
	}
	if !v.Valid {
		return auditLossRefused("the sealed chain does not verify (%s): investigate before completing seal #%d", v.Reason, last.Seq)
	}
	if got := v.ChainedEvents + anchorPurgedEvents(f.anchor); got < last.After.Events {
		return auditLossRefused("seal #%d recorded %d surviving events, only %d remain: rows were removed since, investigate", last.Seq, last.After.Events, got)
	}
	if last.After.HeadID != 0 {
		hash, found, err := c.storage.AuditEntryHashByID(ctx, last.After.HeadID)
		if err != nil {
			return err
		}
		if !found || hash != last.After.HeadHash {
			return auditLossRefused("audit event #%d, the surviving head seal #%d recorded, is missing or rewritten: investigate", last.After.HeadID, last.Seq)
		}
	}
	// Rows certified after the seal are not what it recorded as surviving. A
	// checkpoint, high-water mark or state pin signed under the current seal
	// list (this acceptance's re-seal, or a server since) only ever certified
	// the sealed chain, so one that certifies a head or count the chain no
	// longer has is a new loss. Completing over it would lower the mark and
	// seal the loss unrecorded.
	certs, err := c.auditLossSealedCertifications(ctx, f, last)
	if err != nil {
		return err
	}
	for _, cert := range certs {
		if cert.Events > v.ChainedEvents+anchorPurgedEvents(f.anchor) {
			return auditLossRefused("%s certifies %d events through #%d under seal #%d, only %d remain: rows certified after the seal are gone, which seal #%d did not accept; investigate",
				cert.Source, cert.Events, cert.HeadID, last.Seq, v.ChainedEvents+anchorPurgedEvents(f.anchor), last.Seq)
		}
		if cert.HeadID == 0 || (f.anchor != nil && cert.HeadID < f.anchor.RowID) {
			continue // purged under the authenticated retention anchor
		}
		hash, found, err := c.storage.AuditEntryHashByID(ctx, cert.HeadID)
		if err != nil {
			return err
		}
		if !found || hash != cert.HeadHash {
			return auditLossRefused("audit event #%d, certified by %s under seal #%d, is missing or rewritten: rows certified after the seal are gone, which seal #%d did not accept; investigate",
				cert.HeadID, cert.Source, last.Seq, last.Seq)
		}
	}
	return nil
}

// auditLossSealedCertifications are the certifications a resumed acceptance
// of seal last must not lower: the latest checkpoint and the high-water mark
// when they authenticate under the current seal binding, and the verification
// state's pin when the state was saved under the current seal count (a
// certification under fewer seals predates the acceptance and certified the
// lost rows). Only this acceptance's own not-yet-rewritten artifacts may be
// skipped: a checkpoint or mark that authenticates under the binding before
// seal last. A removed or garbled certification is not "no certification": a
// latest checkpoint or a mark that authenticates under neither binding, or a
// mark that is missing although seal last recorded a certification before the
// loss (the acceptance overwrites the mark, it never deletes it), is refused.
// After a key change, an artifact still signed under the previous key is
// counted or skipped only as the active transition record names it
// (audit_seal_key_change.go, #3814).
func (c *KeyorixCore) auditLossSealedCertifications(ctx context.Context, f *auditLossFindings, last *auditSeal) ([]AuditSealCount, error) {
	var out []AuditSealCount
	cur, prev := sealBindingOf(f.seals.recs), sealBindingOf(f.seals.recs[:len(f.seals.recs)-1])
	// Signed under the key before a key change (#3814): only what the
	// transition record, MACed by both keys, names with its binding counts.
	carried, err := c.activeAuditSealing(ctx, f.seals.recs)
	if err != nil {
		return nil, err
	}
	const viaKeyChange = " (signed under the previous key, named by the key transition)"
	cp, err := c.storage.LatestAuditCheckpoint(ctx)
	if err != nil {
		return nil, err
	}
	if cp != nil {
		named := carried.binding(auditCheckpointDigest(cp))
		switch {
		case c.checkpointSigMatchesUnder(cp, cur, cp.Signature):
			out = append(out, AuditSealCount{Events: cp.ChainedEvents, HeadID: cp.HeadID, HeadHash: cp.HeadHash, Source: fmt.Sprintf("signed checkpoint #%d", cp.ID)})
		case named == auditCarriedUnder:
			out = append(out, AuditSealCount{Events: cp.ChainedEvents, HeadID: cp.HeadID, HeadHash: cp.HeadHash, Source: fmt.Sprintf("signed checkpoint #%d", cp.ID) + viaKeyChange})
		case c.checkpointSigMatchesUnder(cp, prev, cp.Signature), named == auditCarriedBefore:
			// Signed before this seal: the re-seal has not replaced it yet.
		default:
			return nil, auditLossRefused("the latest checkpoint #%d authenticates neither under seal #%d nor before it (deleted newer checkpoints or a garbled signature, not a half-written acceptance): investigate before completing seal #%d", cp.ID, last.Seq, last.Seq)
		}
	}
	val, ok, err := c.storage.GetSystemMetadata(ctx, auditHighWaterKey)
	if err != nil {
		return nil, err
	}
	if ok {
		hw, b, sig, parsed := parseAuditHighWaterSealed(val)
		named := carried.binding(auditDigest(val))
		switch {
		case parsed && b == cur && c.checkpointSigMatchesUnder(hw, cur, sig):
			out = append(out, AuditSealCount{Events: hw.ChainedEvents, HeadID: hw.HeadID, HeadHash: hw.HeadHash, Source: "the signed high-water mark"})
		case parsed && b == cur && named == auditCarriedUnder:
			out = append(out, AuditSealCount{Events: hw.ChainedEvents, HeadID: hw.HeadID, HeadHash: hw.HeadHash, Source: "the signed high-water mark" + viaKeyChange})
		case parsed && b == prev && (c.checkpointSigMatchesUnder(hw, prev, sig) || named == auditCarriedBefore):
			// Signed before this seal: the re-seal has not lowered it yet.
		default:
			return nil, auditLossRefused("the audit high-water mark authenticates neither under seal #%d nor before it (garbled or relabelled, not a half-written acceptance): investigate before completing seal #%d", last.Seq, last.Seq)
		}
	} else if last.Before != nil {
		return nil, auditLossRefused("the audit high-water mark is missing although seal #%d recorded %d certified events (%s): an acceptance overwrites the mark, it never deletes it; investigate before completing seal #%d", last.Seq, last.Before.Events, last.Before.Source, last.Seq)
	}
	if p := f.state.Pin; p != nil && f.state.Seals == len(f.seals.recs) {
		out = append(out, AuditSealCount{Events: p.Events, HeadID: p.HeadID, HeadHash: p.HeadHash, Source: "the signed verification state"})
	}
	// The host witness (SQLite installs) lives outside the database, so a
	// rollback of every row above (a copy from before the acceptance put
	// back) does not reach it. Under the seal it certified the sealed chain
	// and what followed; before it, it is this acceptance's not-yet-rewritten
	// mirror (possibly signed under the key before a key change, which
	// re-signs the mark but not the witness). Anything else is refused, as
	// `admin restore` refuses a damaged witness.
	wcp, wb, wsig, found, err := c.readAuditWitness()
	if err != nil {
		return nil, auditLossRefused("the host's high-water witness file cannot be used (%v): a damaged witness is not treated as absent; investigate before completing seal #%d", err, last.Seq)
	}
	if found {
		switch {
		case wb == cur && c.checkpointSigMatchesUnder(wcp, cur, wsig):
			out = append(out, AuditSealCount{Events: wcp.ChainedEvents, HeadID: wcp.HeadID, HeadHash: wcp.HeadHash, Source: "the host's high-water witness file"})
		case wb == cur && carried.binding(auditHighWaterDigestOf(wcp, wb, wsig)) == auditCarriedUnder:
			// The mirror of a mark the transition names under this seal.
			out = append(out, AuditSealCount{Events: wcp.ChainedEvents, HeadID: wcp.HeadID, HeadHash: wcp.HeadHash, Source: "the host's high-water witness file" + viaKeyChange})
		case wb == prev && (wcp.KeyVersion != c.auditCkptKeyVersion || c.checkpointSigMatchesUnder(wcp, prev, wsig)):
			// Written before this seal: the re-seal has not replaced it yet.
		default:
			return nil, auditLossRefused("the host's high-water witness file authenticates neither under seal #%d nor before it (garbled or replaced, not a half-written acceptance): investigate before completing seal #%d", last.Seq, last.Seq)
		}
	}
	return out, nil
}

// readAuditWitness reads the host's high-water witness file. found is false
// only when no witness is configured or the file does not exist; one that is
// not a regular file or does not parse as a mark is an error, never absent.
func (c *KeyorixCore) readAuditWitness() (cp *models.AuditCheckpoint, b auditSealBinding, sig string, found bool, err error) {
	path := c.auditHighWaterWitnessPath
	if path == "" {
		return nil, b, "", false, nil
	}
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, b, "", false, nil
	}
	if err != nil {
		return nil, b, "", false, err
	}
	if !fi.Mode().IsRegular() {
		return nil, b, "", false, fmt.Errorf("%s is not a regular file", path)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- the configured witness path beside the database
	if err != nil {
		return nil, b, "", false, err
	}
	cp, b, sig, ok := parseAuditHighWaterSealed(string(data))
	if !ok {
		return nil, b, "", false, fmt.Errorf("%s does not parse as a high-water mark", path)
	}
	return cp, b, sig, true, nil
}

// auditLossResumeAccepted is what a resumed acceptance clears: what seal s
// accepted, plus any discontinuity or failure the state carries that s does
// not list (one a server recorded in between), so none is dropped silently.
func auditLossResumeAccepted(s *auditSeal, st *auditVerifyState) []AuditSealAccepted {
	out := slices.Clone(s.Accepted)
	has := func(what, kind, reason string) bool {
		return slices.ContainsFunc(out, func(a AuditSealAccepted) bool { return a.What == what && a.Kind == kind && a.Reason == reason })
	}
	if d := st.Discontinuity; d != nil && !has("discontinuity", d.Kind, d.Reason) {
		at := d.DetectedAt
		out = append(out, AuditSealAccepted{What: "discontinuity", Kind: d.Kind, Reason: d.Reason, DetectedAt: &at})
	}
	if fl := st.Failure; fl != nil && !has("failure", fl.Source, fl.Reason) {
		at := fl.DetectedAt
		out = append(out, AuditSealAccepted{What: "failure", Kind: fl.Source, Reason: fl.Reason, DetectedAt: &at})
	}
	return out
}

// namedIDs are the ids an operator names for s: the row resuming each gap and
// the missing certified head of a truncation.
func (s *auditSeal) namedIDs() []uint {
	var ids []uint
	for _, g := range s.Gaps {
		ids = append(ids, g.ResumeID)
	}
	if t := s.Truncation; t != nil {
		ids = append(ids, t.CertifiedHeadID)
	}
	slices.Sort(ids)
	return ids
}

// sameIDs reports whether a and b name the same ids (order ignored).
func sameIDs(a, b []uint) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

// auditEventByID reads one audit row with its hashes (nil when absent).
func (c *KeyorixCore) auditEventByID(ctx context.Context, id uint) (*models.AuditEvent, error) {
	if id == 0 {
		return nil, nil
	}
	after := id - 1
	evs, _, err := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{AfterID: &after, UpToID: &id, Ascending: true, PageSize: 1, Count: storage.AuditCountNone})
	if err != nil || len(evs) == 0 || evs[0].ID != id {
		return nil, err
	}
	return evs[0], nil
}

// planAuditGaps checks each named id where the walk breaks: the row must be
// intact (it recomputes), current-encoded, and its prev_hash must name a row
// that is gone (neither the row before it nor the one before that: an inserted
// row is not a loss). Ids the walk does not break at are returned in rest (a
// truncation candidate).
func (c *KeyorixCore) planAuditGaps(ctx context.Context, f *auditLossFindings, ids []uint) (gaps []AuditSealGap, rest []uint, err error) {
	for _, id := range ids {
		all := sealedGaps(f.seals.recs, gaps)
		v, err := c.walkAuditChainGaps(ctx, storage.AuditChainSegment{Anchor: f.anchor}, all)
		if err != nil {
			return nil, nil, err
		}
		if v.Valid {
			rest = append(rest, id)
			continue
		}
		at := uint(0)
		if v.FirstBrokenID != nil {
			at = *v.FirstBrokenID
		}
		switch {
		case at != id:
			return nil, nil, auditLossRefused("the walk breaks at audit event #%d, not at #%d (%s)", at, id, v.Reason)
		case strings.Contains(v.Reason, "valid under the pre-#1452"):
			return nil, nil, auditLossRefused("audit event #%d is in the pre-#1452 encoding: an old encoding, not a loss (run the chain-encoding migration)", id)
		case !strings.Contains(v.Reason, "prev_hash does not link"):
			return nil, nil, auditLossRefused("audit event #%d does not verify (%s): that is a modified row, not a lost one", id, v.Reason)
		}
		row, err := c.auditEventByID(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		if row == nil || row.EntryHash == "" {
			return nil, nil, auditLossRefused("audit event #%d cannot be read back with its hash", id)
		}
		pin, err := c.storage.VerifyAuditChainSegment(ctx, storage.AuditChainSegment{AfterID: id, SeedHash: row.EntryHash, ThroughID: id})
		if err != nil {
			return nil, nil, err
		}
		if !pin.Valid {
			return nil, nil, auditLossRefused("audit event #%d itself does not verify (%s): a modified row, not a lost one", id, pin.Reason)
		}
		pre, err := c.walkAuditChainGaps(ctx, storage.AuditChainSegment{Anchor: f.anchor, ThroughID: id - 1}, all)
		if err != nil {
			return nil, nil, err
		}
		if !pre.Valid {
			return nil, nil, auditLossRefused("the chain before audit event #%d does not verify (%s)", id, pre.Reason)
		}
		if pre.HeadID+1 == id {
			// The walk reads in id order: with no id between them, nothing
			// was deleted, so the row before (it still recomputes, so its
			// hash was recomputed too) was rewritten (#3802).
			return nil, nil, auditLossRefused("audit event #%d's prev_hash does not link to #%d, the row right before it, and no id is missing between them: a rewritten row, not a lost one; investigate", id, pre.HeadID)
		}
		if pre.HeadID > 1 {
			// The chained row before pre's head (the walk reads in id order).
			q, err := c.walkAuditChainGaps(ctx, storage.AuditChainSegment{Anchor: f.anchor, ThroughID: pre.HeadID - 1}, all)
			if err != nil {
				return nil, nil, err
			}
			if q.Valid && q.HeadID != 0 && q.HeadHash == row.PrevHash {
				return nil, nil, auditLossRefused("audit event #%d links to #%d: audit event #%d was inserted between them, nothing was lost", id, q.HeadID, pre.HeadID)
			}
		}
		gaps = append(gaps, AuditSealGap{LastGoodID: pre.HeadID, LastGoodHash: pre.HeadHash, ResumeID: id, ResumeHash: row.EntryHash})
	}
	return gaps, rest, nil
}

// auditLossBefore is the newest authenticated certification before the loss:
// the largest of the latest checkpoint, the high-water mark, the state pin and
// the host witness (witness, from auditLossWitness; nil when there is none).
// The witness lives outside the database, so after an in-database rollback of
// the metadata it is the one certification that still counts the lost rows.
func (c *KeyorixCore) auditLossBefore(ctx context.Context, f *auditLossFindings, witness *AuditSealCount) (*AuditSealCount, error) {
	var best *AuditSealCount
	take := func(events int64, id uint, hash, source string) {
		if events > 0 && (best == nil || events > best.Events) {
			best = &AuditSealCount{Events: events, HeadID: id, HeadHash: hash, Source: source}
		}
	}
	cp, err := c.storage.LatestAuditCheckpoint(ctx)
	if err != nil {
		return nil, err
	}
	if cp != nil && c.checkpointSignatureValid(cp) {
		take(cp.ChainedEvents, cp.HeadID, cp.HeadHash, fmt.Sprintf("signed checkpoint #%d", cp.ID))
	}
	hw, err := c.authenticatedHighWaterBase(ctx)
	if err != nil {
		return nil, err
	}
	if hw != nil {
		take(hw.ChainedEvents, hw.HeadID, hw.HeadHash, "signed high-water mark")
	}
	if p := f.state.Pin; p != nil && f.state.Seals == len(f.seals.recs) {
		take(p.Events, p.HeadID, p.HeadHash, "signed verification state")
	}
	if witness != nil {
		take(witness.Events, witness.HeadID, witness.HeadHash, witness.Source)
	}
	return best, nil
}

// auditLossWitness reads the host's high-water witness for a new acceptance
// over the seal list f holds. It returns the certification when the witness
// authenticates under that list, a note when it is present but does not
// authenticate under the current key (written before a key change; nothing
// to count, and the re-seal replaces it), and a refusal when it is damaged or
// authenticates under a seal list the database does not hold: a longer list,
// or another list of the same length, means the database, seal record
// included, was rolled back past the witness's last write.
func (c *KeyorixCore) auditLossWitness(f *auditLossFindings) (*AuditSealCount, string, error) {
	w, wb, sig, found, err := c.readAuditWitness()
	if err != nil {
		return nil, "", auditLossRefused("the host's high-water witness file cannot be used (%v): a damaged witness is not treated as absent; investigate", err)
	}
	if !found {
		return nil, "", nil
	}
	pre := sealBindingOf(f.seals.recs)
	switch {
	case !c.checkpointSigMatchesUnder(w, wb, sig):
		return nil, fmt.Sprintf("present but it does not authenticate under the current key (key version %q, written before a key change); it is replaced", w.KeyVersion), nil
	case wb == pre:
		return &AuditSealCount{Events: w.ChainedEvents, HeadID: w.HeadID, HeadHash: w.HeadHash, Source: "the host's high-water witness file"}, "", nil
	case wb.N >= pre.N:
		return nil, "", auditLossRefused("%s: if this was a sanctioned `admin restore --allow-rollback`, compare the trail with an external anchor, move the witness file aside and re-run", auditWitnessRollback(w, wb, pre))
	}
	// Written under an earlier seal list (a re-seal without a witness path):
	// it certified the chain before an accepted loss and is replaced.
	return nil, fmt.Sprintf("written under %d seal(s), before an earlier accepted loss; it is replaced", wb.N), nil
}

// auditWitnessRollback describes a witness that authenticates under a seal
// list the database does not hold.
func auditWitnessRollback(w *models.AuditCheckpoint, wb, db auditSealBinding) string {
	return fmt.Sprintf("the host's high-water witness file certifies %d events through #%d under %d accepted loss(es) (seal digest %s), but the database holds %d seal(s) (digest %s): the database, seal record included, was rolled back or replaced past the witness",
		w.ChainedEvents, w.HeadID, wb.N, shortHash(wb.Digest), db.N, shortHash(db.Digest))
}

// auditLossBeforeHeadNamed refuses a plan whose newest certification before
// the loss names a head that is gone (and not purged under the authenticated
// retention anchor) unless the plan accepts it as the truncated head: the
// record would otherwise place the tail loss inside a gap, and the re-seal
// would lower that certification without naming where its rows went.
func (c *KeyorixCore) auditLossBeforeHeadNamed(ctx context.Context, f *auditLossFindings, before *AuditSealCount, t *AuditSealTruncation) error {
	if before == nil || before.HeadID == 0 || (t != nil && t.CertifiedHeadID == before.HeadID) {
		return nil
	}
	if f.anchor != nil && before.HeadID < f.anchor.RowID {
		return nil
	}
	hash, found, err := c.storage.AuditEntryHashByID(ctx, before.HeadID)
	switch {
	case err != nil:
		return err
	case !found:
		return auditLossRefused("%s certifies %d events through #%d, and audit event #%d is gone: name it as well (--first-broken-id %d) so the seal records the tail loss", before.Source, before.Events, before.HeadID, before.HeadID, before.HeadID)
	case hash != before.HeadHash:
		return auditLossRefused("audit event #%d differs from the head %s certified (rewritten, not lost)", before.HeadID, before.Source)
	}
	return nil
}

// auditWitnessLowerProblem says why the re-seal of the acceptance that moves
// the seal binding from pre to post (the last record names before as its
// newest certification before the loss) must not overwrite the host witness
// with a mark of survivors events ("" when it may). A witness that
// authenticates under post certified rows written after this seal; one under
// pre is lowered only when the record names a certification at least as high
// (the plan the operator confirmed showed it); one under another list of at
// least pre's length is a rollback. A damaged witness is not treated as
// absent.
func (c *KeyorixCore) auditWitnessLowerProblem(pre, post auditSealBinding, before *AuditSealCount, survivors int64) string {
	w, wb, sig, found, err := c.readAuditWitness()
	if err != nil {
		return fmt.Sprintf("the host's high-water witness file cannot be used (%v): a damaged witness is not treated as absent; investigate", err)
	}
	if !found || !c.checkpointSigMatchesUnder(w, wb, sig) {
		return ""
	}
	switch {
	case wb == post:
		if w.ChainedEvents > survivors {
			return fmt.Sprintf("the host's high-water witness file certifies %d events through #%d under the current seal list, only %d remain: rows certified after the seal are gone; investigate",
				w.ChainedEvents, w.HeadID, survivors)
		}
	case wb == pre:
		if w.ChainedEvents > survivors && (before == nil || w.ChainedEvents > before.Events) {
			named := "none"
			if before != nil {
				named = fmt.Sprintf("%d events through #%d, %s", before.Events, before.HeadID, before.Source)
			}
			return fmt.Sprintf("the host's high-water witness file certifies %d events through #%d from before this acceptance, more than the certification its record names (%s): it would be lowered without being named; re-run accept-loss so the plan shows it",
				w.ChainedEvents, w.HeadID, named)
		}
	case wb.N >= pre.N:
		return auditWitnessRollback(w, wb, pre)
	}
	return ""
}

// auditLossAnchor authenticates an export-checkpoint file under the current
// key and any seal list it may have been exported under, and checks that it
// covers the lost range (it certified a head past the last surviving row
// before each gap, or past the surviving head of a truncation).
func (c *KeyorixCore) auditLossAnchor(ctx context.Context, f *auditLossFindings, a *AuditLossAnchor, gaps []AuditSealGap, after AuditSealCount) (*AuditSealAnchor, error) {
	if a.KeyVersion != c.auditCkptKeyVersion {
		return nil, auditLossRefused("the anchor file claims key version %q, not the current %q: it cannot be authenticated with this key", a.KeyVersion, c.auditCkptKeyVersion)
	}
	ok := false
	for k := 0; k <= len(f.seals.recs) && !ok; k++ {
		ok = c.checkpointSigMatchesUnder(&models.AuditCheckpoint{ChainedEvents: a.ChainedEvents, HeadID: a.HeadID, HeadHash: a.HeadHash, KeyVersion: a.KeyVersion}, sealBindingOf(f.seals.recs[:k]), a.Signature)
	}
	if !ok {
		return nil, auditLossRefused("the anchor file does not authenticate under the current checkpoint key")
	}
	covers := len(gaps) == 0 && a.HeadID > after.HeadID
	for _, g := range gaps {
		covers = covers || a.HeadID > g.LastGoodID
	}
	if !covers {
		return nil, auditLossRefused("the anchor file certifies the chain through #%d only: it was exported before the lost rows existed and does not cover the lost range", a.HeadID)
	}
	if hash, found, err := c.storage.AuditEntryHashByID(ctx, a.HeadID); err != nil {
		return nil, err
	} else if found && hash != a.HeadHash {
		return nil, auditLossRefused("audit event #%d differs from the anchor file (rewritten, not lost)", a.HeadID)
	}
	return &AuditSealAnchor{Digest: strings.ToLower(a.Digest), Verified: true, ChainedEvents: a.ChainedEvents, HeadID: a.HeadID, HeadHash: a.HeadHash}, nil
}

// planAuditTruncation accepts a tail loss: the named id must be the missing
// head of the newest authenticated certification, and fewer events survive.
func (c *KeyorixCore) planAuditTruncation(ctx context.Context, f *auditLossFindings, gaps []AuditSealGap, ids []uint, before *AuditSealCount, after AuditSealCount) (*AuditSealTruncation, error) {
	if len(ids) > 1 {
		return nil, auditLossRefused("the walk does not break at audit events %v", ids)
	}
	id := ids[0]
	if before == nil || before.HeadID != id {
		return nil, auditLossRefused("the walk does not break at audit event #%d, and it is not the head a signed checkpoint, high-water mark or verification state certified", id)
	}
	hash, found, err := c.storage.AuditEntryHashByID(ctx, id)
	if err != nil {
		return nil, err
	}
	switch {
	case found && hash == before.HeadHash:
		return nil, auditLossRefused("audit event #%d, the certified head, is present and unchanged: nothing was lost", id)
	case found:
		return nil, auditLossRefused("audit event #%d, the certified head, was rewritten: a modified row, not a lost one", id)
	case after.Events >= before.Events:
		return nil, auditLossRefused("the certified head #%d is gone but %d events survive of %d certified: not a proven loss", id, after.Events, before.Events)
	}
	// The row the chain ended on below the lost head.
	surviving := uint(0)
	if id > 1 {
		w, err := c.walkAuditChainGaps(ctx, storage.AuditChainSegment{Anchor: f.anchor, ThroughID: id - 1}, sealedGaps(f.seals.recs, gaps))
		if err != nil {
			return nil, err
		}
		surviving = w.HeadID
	}
	return &AuditSealTruncation{CertifiedHeadID: id, CertifiedHeadHash: before.HeadHash, SurvivingHeadID: surviving}, nil
}

// auditLossAccepted lists the alarms the acceptance clears, verbatim.
func auditLossAccepted(st *auditVerifyState, gaps []AuditSealGap, t *AuditSealTruncation) []AuditSealAccepted {
	var out []AuditSealAccepted
	for _, g := range gaps {
		out = append(out, AuditSealAccepted{What: "walk", Reason: fmt.Sprintf("audit event #%d's prev_hash does not link to #%d (rows between them removed)", g.ResumeID, g.LastGoodID)})
	}
	if t != nil {
		out = append(out, AuditSealAccepted{What: "checkpoint", Reason: fmt.Sprintf("audit event #%d, the certified head, is missing (tail-truncation)", t.CertifiedHeadID)})
	}
	if d := st.Discontinuity; d != nil {
		at := d.DetectedAt
		out = append(out, AuditSealAccepted{What: "discontinuity", Kind: d.Kind, Reason: d.Reason, DetectedAt: &at})
	}
	if fl := st.Failure; fl != nil {
		at := fl.DetectedAt
		out = append(out, AuditSealAccepted{What: "failure", Kind: fl.Source, Reason: fl.Reason, DetectedAt: &at})
	}
	return out
}

// AuditLossResult is what AcceptAuditLoss wrote.
type AuditLossResult struct {
	Seq        int
	Digest     string
	Checkpoint *models.AuditCheckpoint
	// HighWater is the new signed high-water value (for the witness file).
	HighWater string
}

// AcceptAuditLoss writes plan (from PlanAuditLossAcceptance in the same
// process, under the same exclusive lock). Each step is idempotent, so a
// re-run after a crash finishes the acceptance.
func (c *KeyorixCore) AcceptAuditLoss(ctx context.Context, plan *AuditLossPlan) (*AuditLossResult, error) {
	if plan == nil || plan.seal == nil {
		return nil, errors.New("accept-loss: no plan")
	}
	if plan.Resume && !plan.resumeNamed {
		return nil, auditLossRefused("nothing was written: this run would complete the unfinished seal #%d, recorded by %q; read its plan and, only if you started that acceptance, re-run with --resume-seal %s",
			plan.Seq, plan.seal.Operator, plan.ResumeDigest)
	}
	res := &AuditLossResult{Seq: plan.Seq}
	err := c.storage.WithAuditCheckpointLock(ctx, func(ctx context.Context) error {
		set, err := c.loadAuditSeals(ctx)
		if err != nil {
			return err
		}
		recs := set.recs
		if !plan.Resume {
			if set.problem != "" || len(recs) != plan.Seq-1 {
				return fmt.Errorf("accept-loss: the seal record changed since the plan was made")
			}
			r := plan.seal
			if len(recs) > 0 {
				r.Prev = recs[len(recs)-1].digest()
			}
			if r.payload, err = json.Marshal(r); err != nil {
				return err
			}
			r.kid = c.auditCkptKeyVersion
			r.mac = auditSealMAC(c.auditCkptKey, r.kid, r.payload)
			// The witness the re-seal will lower must be the one the plan
			// named: checked before anything is written.
			if why := c.auditWitnessLowerProblem(sealBindingOf(recs), sealBindingOf(append(slices.Clone(recs), r)), r.Before, r.After.Events); why != "" {
				return fmt.Errorf("accept-loss: %s", why)
			}
			if err := c.storage.SetSystemMetadata(ctx, auditSealsKey, encodeAuditSeals(append(recs, r))); err != nil {
				return fmt.Errorf("accept-loss: write the seal record: %w", err)
			}
			if err := c.sealHook("record"); err != nil {
				return err
			}
			if set, err = c.loadAuditSeals(ctx); err != nil {
				return err
			}
		}
		last := set.recs[len(set.recs)-1]
		res.Digest = last.digest()
		if set.pending {
			if !c.writeAuditEventFull(ctx, auditSealEvent, nil, nil, nil, "", auditSealEventText(last)) {
				return fmt.Errorf("accept-loss: the in-chain %s event could not be appended (the seal stays incomplete and reads broken; re-run)", auditSealEvent)
			}
			if err := c.sealHook("event"); err != nil {
				return err
			}
			if set, err = c.loadAuditSeals(ctx); err != nil {
				return err
			}
		}
		if set.problem != "" {
			return fmt.Errorf("accept-loss: the seal record does not verify after writing it: %s", set.problem)
		}
		cp, hw, err := c.resealAuditCheckpoint(ctx)
		if err != nil {
			return err
		}
		res.Checkpoint, res.HighWater = cp, hw
		if err := c.sealHook("high-water"); err != nil {
			return err
		}
		return c.saveSealedAuditVerifyState(ctx, last.Seq, plan.Accepted, cp)
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (c *KeyorixCore) sealHook(step string) error {
	if c.auditSealHook == nil {
		return nil
	}
	return c.auditSealHook(step)
}

// resealAuditCheckpoint writes a checkpoint and high-water mark of the sealed
// chain under the current seal binding. The mark is overwritten, not advanced:
// it is lowered to what survives (the accepted loss). The witness is lowered
// with it only from the binding before the newest seal, and only as far as
// that seal's record names (auditWitnessLowerProblem).
func (c *KeyorixCore) resealAuditCheckpoint(ctx context.Context) (*models.AuditCheckpoint, string, error) {
	anchor, err := c.loadAuditRetentionAnchor(ctx)
	if err != nil {
		return nil, "", err
	}
	v, err := c.walkAuditChain(ctx, storage.AuditChainSegment{Anchor: anchor})
	if err != nil {
		return nil, "", err
	}
	if !v.Valid {
		return nil, "", fmt.Errorf("accept-loss: the sealed chain does not verify: %s", v.Reason)
	}
	cp := &models.AuditCheckpoint{ChainedEvents: v.ChainedEvents + anchorPurgedEvents(anchor), HeadID: v.HeadID, HeadHash: v.HeadHash, KeyVersion: c.auditCkptKeyVersion}
	bind := c.sealBinding()
	if cp.Signature, err = c.signCheckpointUnder(cp, bind); err != nil {
		return nil, "", fmt.Errorf("accept-loss: %w", err)
	}
	// A witness under the current seal list certified rows written after this
	// seal, and one from before it may count rows the record does not name;
	// lowering either would destroy the evidence of their loss. Checked
	// before anything is written.
	c.auditSealMu.Lock()
	recs := c.auditSealRecs
	c.auditSealMu.Unlock()
	if len(recs) == 0 {
		return nil, "", errors.New("accept-loss: no seal record to re-seal under")
	}
	last := recs[len(recs)-1]
	if why := c.auditWitnessLowerProblem(sealBindingOf(recs[:len(recs)-1]), bind, last.Before, cp.ChainedEvents); why != "" {
		return nil, "", fmt.Errorf("accept-loss: %s", why)
	}
	if err := c.storage.CreateAuditCheckpoint(ctx, cp); err != nil {
		return nil, "", fmt.Errorf("accept-loss: write the checkpoint: %w", err)
	}
	c.anchorCheckpoint(ctx, cp)
	if err := c.sealHook("checkpoint"); err != nil {
		return nil, "", err
	}
	hw := auditHighWaterValueSealed(cp, bind, cp.Signature)
	if err := c.storage.SetSystemMetadata(ctx, auditHighWaterKey, hw); err != nil {
		return nil, "", fmt.Errorf("accept-loss: write the high-water mark: %w", err)
	}
	if c.auditHighWaterWitnessPath != "" {
		if err := writeFileAtomic0600(c.auditHighWaterWitnessPath, []byte(hw)); err != nil {
			return nil, "", fmt.Errorf("accept-loss: update the rollback-protection witness: %w", err)
		}
	}
	return cp, hw, nil
}

// saveSealedAuditVerifyState saves the state after seal seq: what the plan
// accepted is moved to the accepted list, the pin and last tail check restart
// at cp, and no full verification is claimed (not_proven until one completes,
// then sealed).
func (c *KeyorixCore) saveSealedAuditVerifyState(ctx context.Context, seq int, accepted []AuditSealAccepted, cp *models.AuditCheckpoint) error {
	prev, _, err := c.loadAuditVerifyStateUnobserved(ctx)
	if err != nil {
		return err
	}
	if prev.Seals == seq && prev.Discontinuity == nil {
		return nil // saved by an earlier run
	}
	st := &auditVerifyState{V: 1, KeyEpoch: prev.KeyEpoch, Accepted: append(slices.Clone(prev.Accepted), accepted...)}
	st.Gen = max(prev.Gen, c.auditVerifyGenSeen.Load(), c.auditVerifyFailureGenFloor()) + 1
	now := c.now()
	st.LastCheck = &auditTailCheck{At: now, Valid: true, CheckpointID: cp.ID, ThroughID: cp.HeadID, HeadHash: cp.HeadHash,
		CertifiedEvents: cp.ChainedEvents, ChainedEvents: cp.ChainedEvents, Checkpointed: true}
	st.Pin = &auditVerifyPin{Events: cp.ChainedEvents, HeadID: cp.HeadID, HeadHash: cp.HeadHash}
	if err := c.saveAuditVerifyState(ctx, st); err != nil {
		return fmt.Errorf("accept-loss: save the verification state: %w", err)
	}
	return nil
}

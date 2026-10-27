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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

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
	// Resume: an earlier acceptance stopped before it finished; this run
	// completes it and writes no new record.
	Resume bool

	seal *auditSeal
}

// Describe is the human summary the command prints before confirming.
func (p *AuditLossPlan) Describe() []string {
	var out []string
	if p.Resume {
		out = append(out, fmt.Sprintf("Seal #%d was recorded but its acceptance did not finish; this run completes it (no new record).", p.Seq))
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
	f, err := c.auditLossPreflight(ctx)
	if err != nil {
		return nil, err
	}
	if f.resume {
		last := f.seals.recs[len(f.seals.recs)-1]
		if err := c.auditLossResumeCheck(ctx, f, last); err != nil {
			return nil, err
		}
		return &AuditLossPlan{Seq: last.Seq, Gaps: last.Gaps, Truncation: last.Truncation, Before: last.Before, After: last.After,
			LostEvents: last.LostEvents, Anchor: last.Anchor, Accepted: last.Accepted, Resume: true, seal: last}, nil
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

	before, err := c.auditLossBefore(ctx, f)
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
	if before != nil && before.HeadID != 0 {
		through, err := c.walkAuditChainGaps(ctx, storage.AuditChainSegment{Anchor: f.anchor, ThroughID: before.HeadID}, all)
		if err != nil {
			return nil, err
		}
		if lost := before.Events - (through.ChainedEvents + purged); through.Valid && lost > 0 {
			plan.LostEvents = lost
		}
	}
	plan.Accepted = auditLossAccepted(f.state, gaps, plan.Truncation)
	plan.seal = &auditSeal{V: 1, Seq: plan.Seq, At: c.now().UTC(), Operator: strings.TrimSpace(req.Operator), OSUser: req.OSUser,
		Reason: strings.TrimSpace(req.Reason), Evidence: strings.ToLower(req.Evidence), Gaps: gaps, Truncation: plan.Truncation,
		Before: plan.Before, After: plan.After, LostEvents: plan.LostEvents, Anchor: plan.Anchor, Accepted: plan.Accepted}
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
	return nil
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
// the largest of the latest checkpoint, the high-water mark and the state pin.
func (c *KeyorixCore) auditLossBefore(ctx context.Context, f *auditLossFindings) (*AuditSealCount, error) {
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
	return best, nil
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
		sig := c.signCheckpointUnder(&models.AuditCheckpoint{ChainedEvents: a.ChainedEvents, HeadID: a.HeadID, HeadHash: a.HeadHash, KeyVersion: a.KeyVersion}, sealBindingOf(f.seals.recs[:k]))
		ok = hmac.Equal([]byte(sig), []byte(a.Signature))
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

// signCheckpointUnder signs cp under seal binding b (the current key).
func (c *KeyorixCore) signCheckpointUnder(cp *models.AuditCheckpoint, b auditSealBinding) string {
	mac := hmac.New(sha256.New, c.auditCkptKey)
	mac.Write([]byte(checkpointCanonicalSealed(cp.ChainedEvents, cp.HeadID, cp.HeadHash, cp.KeyVersion, b)))
	return hex.EncodeToString(mac.Sum(nil))
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
		return c.saveSealedAuditVerifyState(ctx, last, cp)
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
// it is lowered to what survives (the accepted loss).
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
	cp.Signature = c.signCheckpoint(cp)
	if err := c.storage.CreateAuditCheckpoint(ctx, cp); err != nil {
		return nil, "", fmt.Errorf("accept-loss: write the checkpoint: %w", err)
	}
	c.anchorCheckpoint(ctx, cp)
	if err := c.sealHook("checkpoint"); err != nil {
		return nil, "", err
	}
	hw := auditHighWaterValueSealed(cp, c.sealBinding(), c.signCheckpoint(cp))
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

// saveSealedAuditVerifyState saves the state after seal s: what s accepted is
// moved to the accepted list, the pin and last tail check restart at cp, and no
// full verification is claimed (not_proven until one completes, then sealed).
func (c *KeyorixCore) saveSealedAuditVerifyState(ctx context.Context, s *auditSeal, cp *models.AuditCheckpoint) error {
	prev, _, err := c.loadAuditVerifyStateUnobserved(ctx)
	if err != nil {
		return err
	}
	if prev.Seals == s.Seq && prev.Discontinuity == nil {
		return nil // saved by an earlier run
	}
	st := &auditVerifyState{V: 1, KeyEpoch: prev.KeyEpoch, Accepted: append(slices.Clone(prev.Accepted), s.Accepted...)}
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

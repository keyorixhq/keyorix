// audit_seal.go — the record of an accepted audit-row loss (`keyorix-server
// admin audit accept-loss`, docs/design-audit-reseal-options.md option A, the
// eight constraints of docs/design/recovery-options.md §2).
//
// A seal is one record in the audit_seals system_metadata row: which rows were
// lost (a "gap" between two surviving rows, or a "truncation" of certified
// rows), what was certified before the loss, what survives, who accepted it,
// when and why. Records are numbered from 1, each names the digest of the one
// before, and each is MACed with the checkpoint key under its own domain, so a
// DB-level actor can neither forge, alter, reorder nor drop one without the
// key. Deleting, altering, moving or replaying the row reads BROKEN:
//
//   - every record has an in-chain system.audit_loss_accepted event naming its
//     digest, and every such event names a record (a replayed shorter row and
//     a record left without its event fail; a deleted row is caught by the
//     walk, the bound checkpoints and the state's seal count below);
//   - a checkpoint or high-water mark written after a seal signs the v2
//     canonical form, which carries the number of seals and the newest record's
//     digest (checkpointCanonicalSealed), so it authenticates only against the
//     exact seal list it was written under;
//   - the walk steps over a sealed gap only at the exact rows the record names
//     (the last surviving row before it and the first after it, with their
//     hashes), so a moved record breaks the walk;
//   - the signed verification state counts the seals it was saved under.
//
// A sealed chain is never reported valid: every view reports "sealed"
// (AuditVerifyStatusSealed), which says the rows since each seal verify and the
// chain is not whole. Key changes carry the row over like the other signed
// artifacts (audit_key_transition.go: the record names its digest, completion
// re-signs it under the new key before anything else).
package core

import (
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

const (
	// auditSealsKey is the system_metadata row holding every seal record.
	auditSealsKey = "audit_seals" // #nosec G101 -- metadata key name, not a credential
	// auditSealEvent is the in-chain record of an accepted loss.
	auditSealEvent = "system.audit_loss_accepted"
	// auditSealDomain prefixes the record MAC so it can never verify as any
	// other artifact signed with the checkpoint key.
	auditSealDomain = "auditseal-v1\x00"

	// auditDiscSeal: the seal record is missing, altered, replayed or
	// incomplete, or the state disagrees with it.
	auditDiscSeal = "seal record"
)

// AuditSealCount is a certified or surviving chain size in chained + purged
// units, with its head row.
type AuditSealCount struct {
	Events   int64  `json:"events"`
	HeadID   uint   `json:"head_id"`
	HeadHash string `json:"head_hash"`
	Source   string `json:"source,omitempty"`
}

// AuditSealAnchor is the external evidence an acceptance was bound to.
type AuditSealAnchor struct {
	// Digest is the SHA-256 of the anchor file (or the digest the operator gave).
	Digest string `json:"digest"`
	// Verified: the file was supplied, authenticated under the checkpoint key
	// and covers the lost range. False for a digest given without the file.
	Verified      bool   `json:"verified"`
	ChainedEvents int64  `json:"chained_events,omitempty"`
	HeadID        uint   `json:"head_id,omitempty"`
	HeadHash      string `json:"head_hash,omitempty"`
}

// AuditSealGap is one accepted gap: the last chained row before it
// (LastGoodID 0 when the gap starts the chain) and the first row after it, with
// the entry hash each carries (the resume row's covers its prev_hash, which
// names the lost predecessor).
type AuditSealGap struct {
	LastGoodID   uint   `json:"last_good_id"`
	LastGoodHash string `json:"last_good_hash"`
	ResumeID     uint   `json:"resume_id"`
	ResumeHash   string `json:"resume_hash"`
}

// AuditSealTruncation is an accepted tail loss: the certified head that is
// gone and the surviving row the chain ended on when the loss was accepted.
type AuditSealTruncation struct {
	CertifiedHeadID   uint   `json:"certified_head_id"`
	CertifiedHeadHash string `json:"certified_head_hash"`
	SurvivingHeadID   uint   `json:"surviving_head_id"`
}

// AuditSealAccepted is one alarm the acceptance cleared, recorded verbatim.
type AuditSealAccepted struct {
	What       string     `json:"what"` // walk | checkpoint | discontinuity | failure
	Kind       string     `json:"kind,omitempty"`
	Reason     string     `json:"reason"`
	DetectedAt *time.Time `json:"detected_at,omitempty"`
}

// auditSeal is one record. The JSON payload is what the MAC covers and what
// the digest is taken over; the key version is next to it (authenticated by
// the MAC, outside the digest, so re-signing under a new key keeps the digest
// every later checkpoint is bound to).
type auditSeal struct {
	V        int       `json:"v"`
	Seq      int       `json:"seq"`
	Prev     string    `json:"prev"`
	At       time.Time `json:"at"`
	Operator string    `json:"operator"`
	OSUser   string    `json:"os_user"`
	Reason   string    `json:"reason"`
	// Evidence is the digest of the evidence the operator kept (a database
	// file or dump, a verify-audit --json report).
	Evidence string `json:"evidence"`
	// Gaps are the rows lost between surviving rows, in id order; Truncation is
	// set when certified rows at the tail were lost (a clean walk, a signed
	// checkpoint, high-water mark or pin proves it). At least one is present.
	Gaps       []AuditSealGap       `json:"gaps,omitempty"`
	Truncation *AuditSealTruncation `json:"truncation,omitempty"`
	// Before is the newest authenticated certification of the chain before the
	// loss (nil: none, the loss is unmeasured); After what survives.
	Before *AuditSealCount `json:"before,omitempty"`
	After  AuditSealCount  `json:"after"`
	// LostEvents is Before.Events minus the surviving rows through Before's
	// head; -1 when unmeasured.
	LostEvents int64               `json:"lost_events"`
	Anchor     *AuditSealAnchor    `json:"anchor,omitempty"`
	Accepted   []AuditSealAccepted `json:"accepted,omitempty"`

	payload  []byte
	kid, mac string
}

func (s *auditSeal) digest() string { return auditDigest(string(s.payload)) }

// lostRange describes the accepted range in messages.
func (s *auditSeal) lostRange() string {
	lost := "an unmeasured number of events"
	if s.LostEvents >= 0 {
		lost = fmt.Sprintf("%d event(s)", s.LostEvents)
	}
	var where []string
	for _, g := range s.Gaps {
		where = append(where, fmt.Sprintf("between audit event #%d and #%d", g.LastGoodID, g.ResumeID))
	}
	if t := s.Truncation; t != nil {
		where = append(where, fmt.Sprintf("after audit event #%d (certified through #%d)", t.SurvivingHeadID, t.CertifiedHeadID))
	}
	return lost + " " + strings.Join(where, ", ")
}

// sealedGap is a gap with the seal that accepted it.
type sealedGap struct {
	AuditSealGap
	Seq int
}

// auditSealBinding is what a checkpoint written after a seal is bound to: the
// number of seals and the newest record's digest. The zero value (no seal)
// keeps the v1 canonical form; N < 0 is a seal list that cannot be trusted,
// against which nothing authenticates.
type auditSealBinding struct {
	N      int
	Digest string
}

var auditSealBindingUntrusted = auditSealBinding{N: -1}

func sealBindingOf(recs []*auditSeal) auditSealBinding {
	if len(recs) == 0 {
		return auditSealBinding{}
	}
	return auditSealBinding{N: len(recs), Digest: recs[len(recs)-1].digest()}
}

// checkpointCanonicalSealed is the signed byte string of a checkpoint (and
// high-water mark) under binding b: the v1 form without seals, otherwise
// "v2" with the seal count and the newest seal digest ahead of the v1 fields.
func checkpointCanonicalSealed(cpEvents int64, headID uint, headHash, keyVersion string, b auditSealBinding) string {
	if b.N == 0 {
		return fmt.Sprintf("v1\x00%d\x00%d\x00%s\x00%s", cpEvents, headID, headHash, keyVersion)
	}
	return fmt.Sprintf("v2\x00%d\x00%s\x00%d\x00%d\x00%s\x00%s", b.N, b.Digest, cpEvents, headID, headHash, keyVersion)
}

func auditSealMAC(key []byte, kid string, payload []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(auditSealDomain + kid + "\x00"))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func encodeAuditSeals(recs []*auditSeal) string {
	lines := make([]string, len(recs))
	for i, r := range recs {
		lines[i] = strings.Join([]string{"aseal-v1", base64.RawURLEncoding.EncodeToString(r.payload), r.kid, r.mac}, auditVerifyStateSep)
	}
	return strings.Join(lines, "\n")
}

var errAuditSealMalformed = errors.New("the audit_seals record is malformed")

// auditSealShapeValid: at least one loss, gaps in id order, each resuming past
// the row before it.
func auditSealShapeValid(r *auditSeal) bool {
	if len(r.Gaps) == 0 && r.Truncation == nil {
		return false
	}
	var prev uint
	for i, g := range r.Gaps {
		if g.ResumeID == 0 || g.ResumeID <= g.LastGoodID || g.ResumeHash == "" || (i > 0 && g.LastGoodID < prev) {
			return false
		}
		prev = g.ResumeID
	}
	return true
}

// parseAuditSeals decodes the row and checks the records link up (consecutive
// seq from 1, each prev the digest of the record before). MACs are not checked.
func parseAuditSeals(val string) ([]*auditSeal, error) {
	var recs []*auditSeal
	for line := range strings.SplitSeq(val, "\n") {
		parts := strings.Split(line, auditVerifyStateSep)
		if len(parts) != 4 || parts[0] != "aseal-v1" || parts[2] == "" {
			return nil, errAuditSealMalformed
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, errAuditSealMalformed
		}
		r := &auditSeal{}
		if err := json.Unmarshal(payload, r); err != nil || r.V != 1 || !auditSealShapeValid(r) {
			return nil, errAuditSealMalformed
		}
		r.payload, r.kid, r.mac = payload, parts[2], parts[3]
		if n := len(recs); r.Seq != n+1 || (n == 0 && r.Prev != "") || (n > 0 && r.Prev != recs[n-1].digest()) {
			return nil, fmt.Errorf("%w: record #%d does not follow the record before it (seq or prev digest)", errAuditSealMalformed, r.Seq)
		}
		recs = append(recs, r)
	}
	return recs, nil
}

// auditSealSet is the authenticated seal list (recs) or, when it cannot be
// trusted, the reason (problem); bind is what checkpoints are checked against.
type auditSealSet struct {
	recs    []*auditSeal
	problem string
	// pending: the newest record has no in-chain event yet (an acceptance that
	// stopped before it finished); problem says so.
	pending bool
	bind    auditSealBinding
}

// gaps returns every sealed gap in id order.
func (s *auditSealSet) gaps() []sealedGap {
	return sealedGaps(s.recs, nil)
}

// sealedGaps flattens the gaps of recs plus extra (a planned acceptance, Seq
// len(recs)+1) in resume-id order.
func sealedGaps(recs []*auditSeal, extra []AuditSealGap) []sealedGap {
	var out []sealedGap
	for _, r := range recs {
		for _, g := range r.Gaps {
			out = append(out, sealedGap{g, r.Seq})
		}
	}
	for _, g := range extra {
		out = append(out, sealedGap{g, len(recs) + 1})
	}
	slices.SortFunc(out, func(a, b sealedGap) int { return cmp.Compare(a.ResumeID, b.ResumeID) })
	return out
}

// sealBinding is the binding checkpoint signatures are made and checked under:
// the seal list the last loadAuditSeals in this process authenticated. Seals
// change only offline (accept-loss runs with the server stopped), and every
// verification entry point loads them again first.
func (c *KeyorixCore) sealBinding() auditSealBinding {
	c.auditSealMu.Lock()
	defer c.auditSealMu.Unlock()
	return c.auditSealBind
}

var auditSealEventDigestRE = regexp.MustCompile(`\(record ([0-9a-f]{64})\)`)

// auditSealEventText is the description of seal r's in-chain event.
func auditSealEventText(r *auditSeal) string {
	return fmt.Sprintf("audit loss accepted: seal #%d (record %s), %s, by %s (host user %s): %s",
		r.Seq, r.digest(), r.lostRange(), r.Operator, r.OSUser, r.Reason)
}

// loadAuditSeals reads and authenticates the seal row, checks it against the
// in-chain seal events and this process's earlier reads, and makes its binding
// the one checkpoint signatures use. A row that cannot be trusted is returned
// with a problem (and binds checkpoints to nothing), never as "no seals". Only
// a storage failure is an error.
func (c *KeyorixCore) loadAuditSeals(ctx context.Context) (*auditSealSet, error) {
	set, err := c.readAuditSeals(ctx)
	if err != nil {
		return nil, err
	}
	c.auditSealMu.Lock()
	defer c.auditSealMu.Unlock()
	if set.problem == "" && len(set.recs) < c.auditSealSeen {
		set.problem = fmt.Sprintf("the audit_seals record holds %d seal(s), but this server already read %d (the record was replaced by an older one)", len(set.recs), c.auditSealSeen)
	}
	if set.problem != "" {
		set.bind = auditSealBindingUntrusted
	} else {
		set.bind = sealBindingOf(set.recs)
		c.auditSealSeen = max(c.auditSealSeen, len(set.recs))
	}
	c.auditSealBind, c.auditSealRecs = set.bind, set.recs
	return set, nil
}

// auditSealStateText is the reported reason of a sealed state: the seals the
// last load authenticated (the state load checked their count against it).
func (c *KeyorixCore) auditSealStateText(st *auditVerifyState) string {
	c.auditSealMu.Lock()
	recs := c.auditSealRecs
	c.auditSealMu.Unlock()
	if len(recs) == st.Seals {
		return auditSealText(recs)
	}
	return fmt.Sprintf("the audit chain is sealed: %d loss(es) of audit events were accepted with the checkpoint key; the chain is not whole and is never reported valid again", st.Seals)
}

// readAuditSeals is loadAuditSeals without the in-process checks and caching.
func (c *KeyorixCore) readAuditSeals(ctx context.Context) (*auditSealSet, error) {
	if !c.AuditCheckpointsAvailable() {
		return &auditSealSet{}, nil
	}
	val, ok, err := c.storage.GetSystemMetadata(ctx, auditSealsKey)
	if err != nil {
		return nil, err
	}
	if !ok {
		// A deleted row is caught without reading the chain here: the walk
		// breaks at the gap it stepped over, every checkpoint and high-water
		// mark written since is bound to the seal and fails, and the state
		// load compares its own seal count (auditVerifyStateSealProblem) and
		// the in-chain seal events.
		return &auditSealSet{}, nil
	}
	ev, err := c.scanAuditVerifyEvidence(ctx)
	if err != nil {
		return nil, err
	}
	recs, perr := parseAuditSeals(val)
	if perr != nil {
		return &auditSealSet{problem: perr.Error()}, nil
	}
	carried, err := c.auditSealsCarried(ctx, val)
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		if carried {
			continue
		}
		if !hmac.Equal([]byte(auditSealMAC(c.auditCkptKey, c.auditCkptKeyVersion, r.payload)), []byte(r.mac)) {
			if r.kid != c.auditCkptKeyVersion {
				return &auditSealSet{problem: fmt.Sprintf("seal #%d claims key version %q and does not authenticate under the current key version %q (a key change that did not carry it over, or an altered record)", r.Seq, r.kid, c.auditCkptKeyVersion)}, nil
			}
			return &auditSealSet{problem: fmt.Sprintf("seal #%d fails its signature under the current key (forged or altered)", r.Seq)}, nil
		}
	}
	for digest, id := range ev.sealNamed {
		if !auditSealNamed(recs, digest) {
			return &auditSealSet{problem: fmt.Sprintf("audit event #%d names an accepted loss the audit_seals record does not hold (the record was replaced)", id)}, nil
		}
	}
	anchor, err := c.loadAuditRetentionAnchor(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load audit chain re-anchor: %w", err)
	}
	for i, r := range recs {
		if _, named := ev.sealNamed[r.digest()]; named {
			continue
		}
		// A sanctioned purge past the seal's surviving head may have removed
		// the event (it is appended right after that head).
		if anchor != nil && anchor.RowID > r.After.HeadID+1 {
			continue
		}
		set := &auditSealSet{recs: recs, problem: fmt.Sprintf("seal #%d has no in-chain %s event: the acceptance did not finish (re-run admin audit accept-loss), or its event was removed", r.Seq, auditSealEvent)}
		set.pending = i == len(recs)-1
		return set, nil
	}
	return &auditSealSet{recs: recs}, nil
}

func auditSealNamed(recs []*auditSeal, digest string) bool {
	for _, r := range recs {
		if r.digest() == digest {
			return true
		}
	}
	return false
}

// auditSealsCarried reports whether val is the seal row a key transition to the
// current key names and has not completed yet: between the key-file commit and
// CompleteAuditKeyTransition it is still signed under the previous key, and the
// record (MACed under the current key) vouches for its exact bytes.
func (c *KeyorixCore) auditSealsCarried(ctx context.Context, val string) (bool, error) {
	t, err := c.activeAuditKeyTransition(ctx)
	if err != nil || t == nil || t.Seals == "" || t.Seals != auditDigest(val) {
		return false, err
	}
	done, err := c.auditKeyTransitionEventExists(ctx, t)
	return !done, err
}

// resignCarriedSeals re-signs the seal row a key transition names under the
// current key (same payloads, so every digest and checkpoint binding is kept).
// It runs first in CompleteAuditKeyTransition: the checkpoint and high-water
// mark the later steps sign are bound to these seals.
func (c *KeyorixCore) resignCarriedSeals(ctx context.Context, t *auditKeyTransition) (bool, error) {
	val, ok, err := c.storage.GetSystemMetadata(ctx, auditSealsKey)
	if err != nil || !ok || t.Seals == "" || auditDigest(val) != t.Seals {
		return false, err
	}
	recs, perr := parseAuditSeals(val)
	if perr != nil {
		return false, nil
	}
	for _, r := range recs {
		r.kid = c.auditCkptKeyVersion
		r.mac = auditSealMAC(c.auditCkptKey, r.kid, r.payload)
	}
	if err := c.storage.SetSystemMetadata(ctx, auditSealsKey, encodeAuditSeals(recs)); err != nil {
		return false, err
	}
	return true, nil
}

// auditSealsAuthentic reports whether a stored seal row authenticates under the
// current key (the transition record names it only then).
func (c *KeyorixCore) auditSealsAuthentic(val string) bool {
	recs, err := parseAuditSeals(val)
	if err != nil {
		return false
	}
	for _, r := range recs {
		if r.kid != c.auditCkptKeyVersion || !hmac.Equal([]byte(auditSealMAC(c.auditCkptKey, r.kid, r.payload)), []byte(r.mac)) {
			return false
		}
	}
	return true
}

// auditSealText is the reported reason of a sealed chain.
func auditSealText(recs []*auditSeal) string {
	parts := make([]string, len(recs))
	for i, r := range recs {
		parts[i] = fmt.Sprintf("seal #%d at %s by %s: %s (%s)", r.Seq, r.At.UTC().Format(time.RFC3339), r.Operator, r.lostRange(), r.Reason)
	}
	return "the audit chain is sealed: a loss of audit events was accepted with the checkpoint key (" + strings.Join(parts, "; ") +
		"). The rows that remain verify; the chain is not whole and is never reported valid again (docs/operator/audit-chain-break-runbook.md)"
}

// sealedWalkBroken marks v broken at id with reason.
func sealedWalkBroken(v *storage.AuditChainVerification, id uint, reason string) *storage.AuditChainVerification {
	v.Valid = false
	if id != 0 {
		v.FirstBrokenID = &id
	}
	v.Reason = reason
	return v
}

// walkAuditChain is the storage walk of seg with every sealed gap stepped
// over: the rows up to the gap must end exactly on the row the seal names as
// the last surviving one (so nothing reappeared inside the gap), and the walk
// resumes pinned at the seal's first surviving row and its recorded hash (which
// covers that row's prev_hash). A seal list that cannot be trusted reads
// broken. On a valid walk, Seals and SealReason say the chain is sealed.
func (c *KeyorixCore) walkAuditChain(ctx context.Context, seg storage.AuditChainSegment) (*storage.AuditChainVerification, error) {
	set, err := c.loadAuditSeals(ctx)
	if err != nil {
		return nil, err
	}
	if set.problem != "" {
		return sealedWalkBroken(&storage.AuditChainVerification{}, 0, "the audit seal record cannot be trusted: "+set.problem), nil
	}
	out, err := c.walkAuditChainGaps(ctx, seg, set.gaps())
	if err != nil {
		return nil, err
	}
	if out.Valid && len(set.recs) > 0 {
		out.Seals = len(set.recs)
		out.SealReason = auditSealText(set.recs)
	}
	return out, nil
}

// walkAuditChainGaps walks seg, stepping over gaps (sorted by ResumeID).
func (c *KeyorixCore) walkAuditChainGaps(ctx context.Context, seg storage.AuditChainSegment, gaps []sealedGap) (*storage.AuditChainVerification, error) {
	out := &storage.AuditChainVerification{Valid: true}
	cur, first := seg, true
	merge := func(v *storage.AuditChainVerification) {
		out.ChainedEvents += v.ChainedEvents
		if first {
			out.UnchainedEvents = v.UnchainedEvents
			first = false
		}
		out.HeadID, out.HeadHash, out.Truncated = v.HeadID, v.HeadHash, v.Truncated
		if !v.Valid {
			out.Valid, out.FirstBrokenID, out.Reason = false, v.FirstBrokenID, v.Reason
		}
	}
	walked := func() int { return int(out.ChainedEvents + out.UnchainedEvents) }
	for _, g := range gaps {
		if seg.ThroughID != 0 && g.ResumeID > seg.ThroughID {
			break
		}
		if cur.AfterID != 0 && g.ResumeID <= cur.AfterID {
			continue
		}
		if cur.AfterID == 0 && cur.Anchor != nil && g.ResumeID <= cur.Anchor.RowID {
			continue // a sanctioned purge removed the gap
		}
		if g.ResumeID > 1 {
			part := cur
			part.ThroughID = g.ResumeID - 1
			if seg.MaxRows > 0 {
				part.MaxRows = max(seg.MaxRows-walked(), 1)
			}
			v, err := c.storage.VerifyAuditChainSegment(ctx, part)
			if err != nil {
				return nil, err
			}
			merge(v)
			if !out.Valid || out.Truncated {
				return out, nil
			}
		}
		// Without a part walked (the gap starts the chain) HeadID is 0.
		if out.HeadID != g.LastGoodID || (g.LastGoodID != 0 && out.HeadHash != g.LastGoodHash) {
			return sealedWalkBroken(out, g.LastGoodID, fmt.Sprintf(
				"the chain before sealed gap #%d no longer ends on audit event #%d with the hash the seal recorded (it ends on #%d): rows were removed, rewritten or put back around an accepted loss",
				g.Seq, g.LastGoodID, out.HeadID)), nil
		}
		cur = storage.AuditChainSegment{AfterID: g.ResumeID, SeedHash: g.ResumeHash, ThroughID: seg.ThroughID}
		// The pinned resume row is checked (present, recorded hash, recomputes)
		// but not counted by the segment walk: count it here.
		out.ChainedEvents++
		first = false
	}
	if seg.MaxRows > 0 {
		cur.MaxRows = max(seg.MaxRows-walked(), 1)
	}
	var v *storage.AuditChainVerification
	var err error
	if cur.AfterID == 0 && cur.ThroughID == 0 && cur.MaxRows == 0 {
		v, err = c.storage.VerifyAuditChain(ctx, cur.Anchor) // the same walk
	} else {
		v, err = c.storage.VerifyAuditChainSegment(ctx, cur)
	}
	if err != nil {
		return nil, err
	}
	if cur.AfterID != 0 && cur.AfterID != seg.AfterID && !v.Valid && v.FirstBrokenID != nil && *v.FirstBrokenID == cur.AfterID {
		v.Reason = fmt.Sprintf("the first surviving row after a sealed gap: %s", v.Reason)
	}
	merge(v)
	return out, nil
}

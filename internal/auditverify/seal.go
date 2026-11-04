package auditverify

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
)

// Accepted audit losses (`keyorix-server admin audit accept-loss`): the
// audit_seals row written by internal/core/audit_seal.go. Byte-identical,
// independent reimplementation of its parser, MAC and walk rules; the
// differential tests build the fixtures with the real core code path.
const (
	auditSealsKey   = "audit_seals"
	auditSealEvent  = "system.audit_loss_accepted"
	auditSealDomain = "auditseal-v1\x00"
)

// SealGap is one accepted gap (internal/core.AuditSealGap).
type SealGap struct {
	LastGoodID   uint64 `json:"last_good_id"`
	LastGoodHash string `json:"last_good_hash"`
	ResumeID     uint64 `json:"resume_id"`
	ResumeHash   string `json:"resume_hash"`
}

// SealTruncation is an accepted tail loss (internal/core.AuditSealTruncation).
type SealTruncation struct {
	CertifiedHeadID   uint64 `json:"certified_head_id"`
	CertifiedHeadHash string `json:"certified_head_hash"`
	SurvivingHeadID   uint64 `json:"surviving_head_id"`
}

// SealCount is a certified or surviving chain size (chained + purged units).
type SealCount struct {
	Events   int64  `json:"events"`
	HeadID   uint64 `json:"head_id"`
	HeadHash string `json:"head_hash"`
	Source   string `json:"source,omitempty"`
}

// SealAnchor is the anchor an acceptance named (internal/core.AuditSealAnchor):
// the SHA-256 of an export-checkpoint file, verified at acceptance when the
// file was passed (--anchor), recorded only when just its digest was
// (--anchor-sha256).
type SealAnchor struct {
	Digest        string `json:"digest"`
	Verified      bool   `json:"verified"`
	ChainedEvents int64  `json:"chained_events,omitempty"`
	HeadID        uint64 `json:"head_id,omitempty"`
	HeadHash      string `json:"head_hash,omitempty"`
}

// SealSpan is a range of audit event ids, both ends included
// (internal/core.AuditSealSpan).
type SealSpan struct {
	FromID    uint64 `json:"from_id"`
	ThroughID uint64 `json:"through_id"`
}

// Seal is one parsed, not yet authenticated record.
type Seal struct {
	V          int             `json:"v"`
	Seq        int             `json:"seq"`
	Prev       string          `json:"prev"`
	At         time.Time       `json:"at"`
	Operator   string          `json:"operator"`
	OSUser     string          `json:"os_user"`
	Reason     string          `json:"reason"`
	Evidence   string          `json:"evidence"`
	Gaps       []SealGap       `json:"gaps,omitempty"`
	Truncation *SealTruncation `json:"truncation,omitempty"`
	Before     *SealCount      `json:"before,omitempty"`
	After      SealCount       `json:"after"`
	LostEvents int64           `json:"lost_events"`
	Anchor     *SealAnchor     `json:"anchor,omitempty"`
	// Unpinned are the surviving rows before each gap that no signed artifact
	// pinned when the loss was accepted (#3802); absent on older records.
	Unpinned []SealSpan `json:"unpinned,omitempty"`

	payload  []byte
	kid, mac string
}

// Digest is the hex SHA-256 of the record's payload.
func (s *Seal) Digest() string {
	sum := sha256.Sum256(s.payload)
	return hex.EncodeToString(sum[:])
}

// KeyVersion is the key version the record claims it is signed under.
func (s *Seal) KeyVersion() string { return s.kid }

// MACValid reports whether the record's MAC verifies under key.
func (s *Seal) MACValid(key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(auditSealDomain + s.kid + "\x00"))
	mac.Write(s.payload)
	return hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(s.mac))
}

// SealStatus reports what this run found for the seal records.
type SealStatus struct {
	Present bool `json:"present"`
	Records int  `json:"records"`
	// Authenticated: every record verified under the supplied checkpoint key
	// and matches the in-chain events.
	Authenticated bool `json:"authenticated"`
	// Seals are the authenticated records, for the report.
	Seals []SealSummary `json:"seals,omitempty"`
}

// SealSummary is one authenticated record in the report.
type SealSummary struct {
	Seq        int       `json:"seq"`
	At         time.Time `json:"at"`
	Operator   string    `json:"operator"`
	Reason     string    `json:"reason"`
	Evidence   string    `json:"evidence"`
	Gaps       []SealGap `json:"gaps,omitempty"`
	Truncated  bool      `json:"truncated,omitempty"`
	LostEvents int64     `json:"lost_events"`
	Digest     string    `json:"digest"`
	// Anchor is the anchor the acceptance named, checked against --anchor.
	Anchor *SealAnchorCheck `json:"anchor,omitempty"`
	// Unpinned are the surviving rows before the loss that nothing signed
	// pinned at acceptance: a rewrite of them before it cannot be excluded.
	Unpinned []SealSpan `json:"unpinned,omitempty"`
}

// Values of SealAnchorCheck.Check.
const (
	SealAnchorNotSupplied     = "not_supplied"    // no --anchor was passed
	SealAnchorDiffers         = "differs"         // --anchor is another file
	SealAnchorUnauthenticated = "unauthenticated" // the same file, which did not authenticate
	SealAnchorNotCovering     = "not_covering"    // the same file, certified before the lost rows
	SealAnchorMatches         = "matches"         // the same file, authenticated, covers the loss
)

// SealAnchorCheck is a seal's anchor compared with the --anchor of this run:
// the SHA-256 of the supplied file must equal the recorded digest, and the
// file must authenticate and certify a head past the last surviving row before
// a gap (or past a truncation's surviving head), the rule accept-loss applies
// to --anchor. Only --anchor-sha256 digests were never checked before.
type SealAnchorCheck struct {
	Digest string `json:"digest"`
	// VerifiedAtAcceptance: the file itself was checked when the loss was
	// accepted; false when only its digest was recorded.
	VerifiedAtAcceptance bool   `json:"verified_at_acceptance"`
	Check                string `json:"check"`
	Detail               string `json:"detail"`
}

var errSealMalformed = errors.New("the audit_seals record is malformed")

// ParseSeals decodes the stored row and checks the records link up
// (consecutive seq from 1, prev digests) and are well formed, as
// internal/core.parseAuditSeals does. MACs are not checked.
func ParseSeals(val string) ([]*Seal, error) {
	var recs []*Seal
	for line := range strings.SplitSeq(val, "\n") {
		parts := strings.Split(line, "\x1f")
		if len(parts) != 4 || parts[0] != "aseal-v1" || parts[2] == "" {
			return nil, errSealMalformed
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, errSealMalformed
		}
		r := &Seal{}
		if err := json.Unmarshal(payload, r); err != nil || r.V != 1 || !sealShapeValid(r) {
			return nil, errSealMalformed
		}
		r.payload, r.kid, r.mac = payload, parts[2], parts[3]
		if n := len(recs); r.Seq != n+1 || (n == 0 && r.Prev != "") || (n > 0 && r.Prev != recs[n-1].Digest()) {
			return nil, fmt.Errorf("%w: record #%d does not follow the record before it (seq or prev digest)", errSealMalformed, r.Seq)
		}
		recs = append(recs, r)
	}
	return recs, nil
}

func sealShapeValid(r *Seal) bool {
	if len(r.Gaps) == 0 && r.Truncation == nil {
		return false
	}
	var prev uint64
	for i, g := range r.Gaps {
		if g.ResumeID == 0 || g.ResumeID <= g.LastGoodID || g.ResumeHash == "" || (i > 0 && g.LastGoodID < prev) {
			return false
		}
		prev = g.ResumeID
	}
	return true
}

// sealBinding is what checkpoints written after the seals are bound to
// (internal/core.auditSealBinding): N = 0 is the v1 canonical form.
type sealBinding struct {
	N      int
	Digest string
}

func sealBindingOf(recs []*Seal) sealBinding {
	if len(recs) == 0 {
		return sealBinding{}
	}
	return sealBinding{N: len(recs), Digest: recs[len(recs)-1].Digest()}
}

// sealedGap is a gap with the record that accepted it.
type sealedGap struct {
	SealGap
	seq int
}

func sealedGaps(recs []*Seal) []sealedGap {
	var out []sealedGap
	for _, r := range recs {
		for _, g := range r.Gaps {
			out = append(out, sealedGap{g, r.Seq})
		}
	}
	slices.SortFunc(out, func(a, b sealedGap) int { return cmp.Compare(a.ResumeID, b.ResumeID) })
	return out
}

var sealEventDigestRE = regexp.MustCompile(`\(record ([0-9a-f]{64})\)`)

// sealEvent is an in-chain system.audit_loss_accepted row.
type sealEvent struct {
	id     uint64
	digest string
}

// loadedSeals is what loadSeals found: the parsed records (nil when absent),
// whether they authenticated under the supplied key, and why not.
type loadedSeals struct {
	recs          []*Seal
	authenticated bool
	problem       string
}

// loadSeals reads and authenticates the seal row. Without a key the records
// are parsed but never trusted: their gaps are not stepped over, so a sealed
// chain reads BROKEN (fail closed) and the reason says a key is needed.
func loadSeals(ctx context.Context, db *DB, opts Options) (*loadedSeals, error) {
	val, found, err := db.GetSystemMetadata(ctx, auditSealsKey)
	if err != nil || !found {
		return &loadedSeals{}, err
	}
	recs, perr := ParseSeals(val)
	if perr != nil {
		return &loadedSeals{problem: perr.Error()}, nil
	}
	if len(opts.CheckpointKey) == 0 {
		return &loadedSeals{recs: recs, problem: "no --checkpoint-key-file was supplied, so the audit_seals record (accepted audit losses) cannot be authenticated"}, nil
	}
	for _, r := range recs {
		if !r.MACValid(opts.CheckpointKey) {
			return &loadedSeals{recs: recs, problem: fmt.Sprintf("seal #%d (claiming key version %q) fails its signature under the supplied checkpoint key (forged or altered, or the wrong key)", r.Seq, r.kid)}, nil
		}
	}
	return &loadedSeals{recs: recs, authenticated: true}, nil
}

// checkSealEvents applies the in-chain rules once the walk collected the seal
// events: every record has an event naming its digest (unless a sanctioned
// retention purge reached past its surviving head), and every event names a
// record. The caller ran the walk with authenticated seals.
func checkSealEvents(result *Result, s *loadedSeals) {
	named := map[string]uint64{}
	for _, e := range result.sealEvents {
		if e.digest == "" || !slices.ContainsFunc(s.recs, func(r *Seal) bool { return r.Digest() == e.digest }) {
			result.escalate(VerdictBroken, fmt.Sprintf("audit event #%d names an accepted loss the audit_seals record does not hold (the record was replaced)", e.id))
			return
		}
		named[e.digest] = e.id
	}
	for _, r := range s.recs {
		if _, ok := named[r.Digest()]; ok {
			continue
		}
		if result.RetentionGap.Sanctioned && result.RetentionGap.RowID > r.After.HeadID+1 {
			continue
		}
		result.escalate(VerdictBroken, fmt.Sprintf("seal #%d has no in-chain %s event: the acceptance did not finish, or its event was removed", r.Seq, auditSealEvent))
		return
	}
}

// sealsCover reports whether a missing row id lies inside a range a seal after
// the first k records accepted (a gap, or a truncation's lost tail).
func sealsCover(recs []*Seal, k int, id uint64) bool {
	for _, r := range recs[k:] {
		for _, g := range r.Gaps {
			if id > g.LastGoodID && id < g.ResumeID {
				return true
			}
		}
		if t := r.Truncation; t != nil && id > t.SurvivingHeadID && id <= t.CertifiedHeadID {
			return true
		}
	}
	return false
}

func summarizeSeals(recs []*Seal, opts Options, result *Result) []SealSummary {
	out := make([]SealSummary, len(recs))
	for i, r := range recs {
		out[i] = SealSummary{Seq: r.Seq, At: r.At, Operator: r.Operator, Reason: r.Reason, Evidence: r.Evidence,
			Gaps: r.Gaps, Truncated: r.Truncation != nil, LostEvents: r.LostEvents, Digest: r.Digest(),
			Anchor: checkSealAnchor(r, opts, result), Unpinned: r.Unpinned}
	}
	return out
}

// checkSealAnchor compares the anchor a seal names with the --anchor file of
// this run (nil when the seal names none). It reports; it never changes the
// verdict: the file is cross-checked against the live chain on its own
// (crossCheckExternalAnchor), and another file is no evidence against the
// seal. What is left unchecked is listed in what this run does not prove.
func checkSealAnchor(r *Seal, opts Options, result *Result) *SealAnchorCheck {
	if r.Anchor == nil {
		return nil
	}
	c := &SealAnchorCheck{Digest: strings.ToLower(r.Anchor.Digest), VerifiedAtAcceptance: r.Anchor.Verified}
	b := opts.ExternalAnchor
	got := strings.ToLower(opts.ExternalAnchorSHA256)
	switch {
	case b == nil || got == "":
		c.Check, c.Detail = SealAnchorNotSupplied, "not checked: pass that file with --anchor"
	case got != c.Digest:
		c.Check, c.Detail = SealAnchorDiffers, fmt.Sprintf("DIFFERS from the supplied --anchor (sha256 %s): that is another file", got)
	case !result.ExternalAnchor.Authenticated:
		c.Check, c.Detail = SealAnchorUnauthenticated,
			"matches the supplied --anchor, but the file did not authenticate (pass --checkpoint-key-file, or --tsa-roots for a timestamped file)"
	case !sealAnchorCovers(r, b.HeadID):
		c.Check, c.Detail = SealAnchorNotCovering, fmt.Sprintf(
			"matches the supplied --anchor, but it certifies the chain through #%d only: it was exported before the lost rows existed and does not cover the loss", b.HeadID)
	default:
		c.Check, c.Detail = SealAnchorMatches, "matches the supplied --anchor, which authenticates and covers the lost range"
	}
	return c
}

// sealAnchorCovers is accept-loss's coverage rule for --anchor
// (internal/core.auditLossAnchor): a head past the last surviving row before
// some gap, or past a truncation's surviving head.
func sealAnchorCovers(r *Seal, headID uint64) bool {
	for _, g := range r.Gaps {
		if headID > g.LastGoodID {
			return true
		}
	}
	return r.Truncation != nil && headID > r.Truncation.SurvivingHeadID
}

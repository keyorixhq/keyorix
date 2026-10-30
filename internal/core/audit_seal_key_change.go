// audit_seal_key_change.go — an accept-loss left unfinished across a key
// change (rotate-kek, migrate-provider; #3814).
//
// A resumed acceptance skips its own not-yet-rewritten artifacts (a latest
// checkpoint or high-water mark signed under the seal list before its seal)
// and counts every certification signed under the seal list through it
// (auditLossSealedCertifications). Both are recognised by their signature
// under the current checkpoint key. After a key change the artifacts the
// acceptance had not rewritten yet are still signed under the previous key,
// which the new process does not hold, so before this the resume refused them
// as "authenticates neither" and the chain stayed broken.
//
// The key transition is prepared by a process holding the old key, so it
// checks those signatures there and names, in the record both keys MAC
// (audit_key_transition.go), the exact digest of each artifact with the seal
// binding it authenticated under. The resume on the new key relies on that
// naming and on nothing else: an artifact the record does not name, or one
// that authenticated under no seal binding at prepare, is still refused. A
// record names artifacts only for the seal list it was prepared over (the
// newest seal's sequence number and digest), and a chain of key changes is
// followed through the transition into the key the prepare runs under.
package core

import (
	"context"
	"slices"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// auditKeyTransitionSealing is what a key transition record names about the
// seal list it was prepared over: the newest seal (Seq, its digest Seal, which
// pins the whole list through each record's prev digest) and the digests of
// the latest checkpoint and the high-water mark that authenticated under the
// old key, split by binding. Before: under the seals before seal Seq (an
// acceptance's own artifacts its re-seal has not replaced yet). Under: under
// the seals through Seq (certifications of the sealed chain).
type auditKeyTransitionSealing struct {
	Seq    int      `json:"seq"`
	Seal   string   `json:"seal"`
	Before []string `json:"before,omitempty"`
	Under  []string `json:"under,omitempty"`
}

// auditCarriedBinding is how an artifact signed under a previous key is
// vouched for: not named, or named under the seals before / through the
// newest seal.
type auditCarriedBinding int

const (
	auditCarriedNone auditCarriedBinding = iota
	auditCarriedBefore
	auditCarriedUnder
)

// binding returns how s names digest d (none for a nil s).
func (s *auditKeyTransitionSealing) binding(d string) auditCarriedBinding {
	switch {
	case s == nil || d == "":
		return auditCarriedNone
	case slices.Contains(s.Under, d):
		return auditCarriedUnder
	case slices.Contains(s.Before, d):
		return auditCarriedBefore
	}
	return auditCarriedNone
}

// auditSealingCarried returns what the transition into the current key, t,
// names about seal list recs: its Sealing when it was prepared over exactly
// that list (same newest seal), else nil. t must already be authenticated
// under the current key (activeAuditKeyTransition, or the last record of the
// list a prepare extends, checked by the caller).
func auditSealingCarried(t *auditKeyTransition, recs []*auditSeal) *auditKeyTransitionSealing {
	if t == nil || t.Sealing == nil || len(recs) == 0 {
		return nil
	}
	last := recs[len(recs)-1]
	if t.Sealing.Seq != last.Seq || t.Sealing.Seal != last.digest() {
		return nil
	}
	return t.Sealing
}

// activeAuditSealing is auditSealingCarried for the active transition.
func (c *KeyorixCore) activeAuditSealing(ctx context.Context, recs []*auditSeal) (*auditKeyTransitionSealing, error) {
	t, err := c.activeAuditKeyTransition(ctx)
	if err != nil {
		return nil, err
	}
	return auditSealingCarried(t, recs), nil
}

// auditKeyTransitionSealingFor builds the Sealing a key transition prepared now
// (under the current, old key) records, or nil when there is no seal or
// nothing to name. prior is the transition into the current key when it is
// authenticated (its naming carries over to the next key), else nil. An
// untrusted seal list (other than an acceptance stopped before its event) is
// named nothing.
func (c *KeyorixCore) auditKeyTransitionSealingFor(ctx context.Context, prior *auditKeyTransition) (*auditKeyTransitionSealing, error) {
	set, err := c.loadAuditSeals(ctx)
	if err != nil {
		return nil, err
	}
	if len(set.recs) == 0 || (set.problem != "" && !set.pending) {
		return nil, nil
	}
	recs := set.recs
	last := recs[len(recs)-1]
	before, under := sealBindingOf(recs[:len(recs)-1]), sealBindingOf(recs)
	carried := auditSealingCarried(prior, recs)
	s := &auditKeyTransitionSealing{Seq: last.Seq, Seal: last.digest()}
	name := func(d string, authentic func(auditSealBinding) bool) {
		switch {
		case authentic(under) || carried.binding(d) == auditCarriedUnder:
			s.Under = append(s.Under, d)
		case authentic(before) || carried.binding(d) == auditCarriedBefore:
			s.Before = append(s.Before, d)
		}
	}
	cp, err := c.storage.LatestAuditCheckpoint(ctx)
	if err != nil {
		return nil, err
	}
	if cp != nil {
		name(auditCheckpointDigest(cp), func(b auditSealBinding) bool { return c.checkpointSigMatchesUnder(cp, b, cp.Signature) })
	}
	val, ok, err := c.storage.GetSystemMetadata(ctx, auditHighWaterKey)
	if err != nil {
		return nil, err
	}
	if ok {
		hw, hb, sig, parsed := parseAuditHighWaterSealed(val)
		name(auditDigest(val), func(b auditSealBinding) bool { return parsed && hb == b && c.checkpointSigMatchesUnder(hw, b, sig) })
	}
	if len(s.Before) == 0 && len(s.Under) == 0 {
		return nil, nil
	}
	return s, nil
}

// auditHighWaterDigestOf is the digest of a mark (or witness) as stored, from
// its parsed fields: the value a transition record names.
func auditHighWaterDigestOf(cp *models.AuditCheckpoint, b auditSealBinding, sig string) string {
	return auditDigest(auditHighWaterValueSealed(cp, b, sig))
}

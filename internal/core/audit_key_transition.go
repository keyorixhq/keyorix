// audit_key_transition.go — carrying the audit verification state across a
// change of the checkpoint signing key (rotate-kek, migrate-provider).
//
// Construction, reasoning and crash table: docs/design-audit-key-transition.md.
// In short: before the new key files commit, the command (holding both keys)
// verifies everything under the old key and appends a record to the
// audit_key_transitions row naming both key versions, the certified head and
// the digests of the stored state, high-water mark, retention anchor and
// latest checkpoint, MACed by the old key and, over that, by the new one. After
// the commit, CompleteAuditKeyTransition (the command, then every server start)
// re-signs those artifacts under the new key, writes a fresh checkpoint, saves
// the state carrying key_epoch and, last, appends an in-chain
// system.audit_key_transition event. Until the event exists a read accepts the
// old state row through the record. A missing, forged or wrong-epoch record is
// a sticky discontinuity (kind "key transition"), never a silent restart.
package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const (
	// auditKeyTransitionsKey is the system_metadata row holding every record.
	auditKeyTransitionsKey = "audit_key_transitions" // #nosec G101 -- metadata key name, not a credential
	// auditKeyTransitionEvent is the in-chain record of a completed transition.
	auditKeyTransitionEvent = "system.audit_key_transition"
	// auditKeyTransitionDomain prefixes both MACs, so neither can verify as any
	// other artifact signed with the same key.
	auditKeyTransitionDomain = "auditkeytrans-v1\x00"
	auditKeyTransitionSource = "key-transition"
)

// Completion steps, named for CompleteAuditKeyTransition's test hook.
const (
	aktStepAnchor     = "anchor"
	aktStepHighWater  = "high-water"
	aktStepCheckpoint = "checkpoint"
	aktStepState      = "state"
	aktStepEvent      = "event"
)

// auditKeyTransition is one record. The JSON payload is what both MACs cover.
type auditKeyTransition struct {
	V            int       `json:"v"`
	Seq          int       `json:"seq"`
	OldKID       string    `json:"old_kid"`
	NewKID       string    `json:"new_kid"`
	At           time.Time `json:"at"`
	HeadID       uint      `json:"head_id"`
	HeadHash     string    `json:"head_hash"`
	Certified    int64     `json:"certified"`
	ChainValid   bool      `json:"chain_valid"`
	Reason       string    `json:"reason,omitempty"`
	State        string    `json:"state"`
	HighWater    string    `json:"high_water"`
	Anchor       string    `json:"anchor"`
	CheckpointID uint      `json:"checkpoint_id"`
	Checkpoint   string    `json:"checkpoint"`
	Prev         string    `json:"prev"`
	// Reset names the damage of the previous record list this one replaced.
	Reset string `json:"reset,omitempty"`

	payload        []byte
	macOld, macNew string
}

// auditKeyEpoch is what a state row carried over by a transition records.
type auditKeyEpoch struct {
	Seq    int    `json:"seq"`
	Digest string `json:"digest"`
}

func (t *auditKeyTransition) digest() string { return auditDigest(string(t.payload)) }

// auditDigest is the hex SHA-256 of a stored value ("" for an absent one).
func auditDigest(val string) string {
	if val == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(val))
	return hex.EncodeToString(sum[:])
}

// auditCheckpointDigest binds a checkpoint row's signed bytes and signature.
func auditCheckpointDigest(cp *models.AuditCheckpoint) string {
	if cp == nil {
		return ""
	}
	return auditDigest(checkpointCanonical(cp) + "\x00" + cp.Signature)
}

// auditKeyTransitionMAC is HMAC(key, domain || dir || 0 || payload), and for
// the new-key MAC also || 0 || macOld, so the new key attests to the exact
// old-key attestation.
func auditKeyTransitionMAC(key []byte, dir string, payload []byte, macOld string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(auditKeyTransitionDomain + dir + "\x00"))
	mac.Write(payload)
	if dir == "new" {
		mac.Write([]byte("\x00" + macOld))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

func encodeAuditKeyTransitions(recs []*auditKeyTransition) string {
	lines := make([]string, len(recs))
	for i, r := range recs {
		lines[i] = strings.Join([]string{"akt-v1", base64.RawURLEncoding.EncodeToString(r.payload), r.macOld, r.macNew}, auditVerifyStateSep)
	}
	return strings.Join(lines, "\n")
}

var errAuditKeyTransitionMalformed = errors.New("the audit key transition record is malformed")

// parseAuditKeyTransitions decodes the row and checks the records link up:
// consecutive seq from 1, each prev the digest of the record before, each
// old key version the previous record's new one. MACs are not checked here.
func parseAuditKeyTransitions(val string) ([]*auditKeyTransition, error) {
	var recs []*auditKeyTransition
	for line := range strings.SplitSeq(val, "\n") {
		parts := strings.Split(line, auditVerifyStateSep)
		if len(parts) != 4 || parts[0] != "akt-v1" {
			return nil, errAuditKeyTransitionMalformed
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, errAuditKeyTransitionMalformed
		}
		r := &auditKeyTransition{}
		if err := json.Unmarshal(payload, r); err != nil || r.V != 1 || r.OldKID == "" || r.NewKID == "" || r.OldKID == r.NewKID {
			return nil, errAuditKeyTransitionMalformed
		}
		r.payload, r.macOld, r.macNew = payload, parts[2], parts[3]
		if n := len(recs); r.Seq != n+1 || (n == 0 && r.Prev != "") ||
			(n > 0 && (r.Prev != recs[n-1].digest() || r.OldKID != recs[n-1].NewKID)) {
			return nil, fmt.Errorf("%w: record #%d does not follow the record before it (seq, prev digest or key version)", errAuditKeyTransitionMalformed, r.Seq)
		}
		recs = append(recs, r)
	}
	return recs, nil
}

// loadAuditKeyTransitions reads and parses the row (nil, false when absent).
// A malformed row is returned as a non-storage error the callers report.
func (c *KeyorixCore) loadAuditKeyTransitions(ctx context.Context) (recs []*auditKeyTransition, found bool, perr, err error) {
	val, ok, err := c.storage.GetSystemMetadata(ctx, auditKeyTransitionsKey)
	if err != nil || !ok {
		return nil, false, nil, err
	}
	recs, perr = parseAuditKeyTransitions(val)
	return recs, true, perr, nil
}

// activeAuditKeyTransition returns the last record when it moved to the
// current key and its new-key MAC verifies.
func (c *KeyorixCore) activeAuditKeyTransition(ctx context.Context) (*auditKeyTransition, error) {
	recs, found, perr, err := c.loadAuditKeyTransitions(ctx)
	if err != nil || !found || perr != nil {
		return nil, err
	}
	last := recs[len(recs)-1]
	if last.NewKID != c.auditCkptKeyVersion || !c.auditKeyTransitionNewMACValid(last) {
		return nil, nil
	}
	return last, nil
}

func (c *KeyorixCore) auditKeyTransitionNewMACValid(r *auditKeyTransition) bool {
	return hmac.Equal([]byte(auditKeyTransitionMAC(c.auditCkptKey, "new", r.payload, r.macOld)), []byte(r.macNew))
}

// decodeAuditVerifyStateCarried is decodeAuditVerifyState that also accepts a
// row signed under the previous key when the active transition record names
// its exact digest and its completion event is not in the chain yet: the
// window between the key-file commit and the state save of completion. Once
// the event exists the state was saved under the new key, so the old row put
// back is a rollback and stays a discontinuity. The accepted state carries
// key_epoch, so the next save keeps the link.
func (c *KeyorixCore) decodeAuditVerifyStateCarried(ctx context.Context, val string) (*auditVerifyState, string, string, error) {
	s, kind, why := c.decodeAuditVerifyState(val)
	if s != nil {
		return s, "", "", nil
	}
	t, err := c.activeAuditKeyTransition(ctx)
	if err != nil || t == nil || t.State != auditDigest(val) {
		return nil, kind, why, err
	}
	if done, err := c.auditKeyTransitionEventExists(ctx, t); err != nil || done {
		return nil, kind, why, err
	}
	parts := strings.Split(val, auditVerifyStateSep)
	if len(parts) != 3 {
		return nil, kind, why, nil
	}
	payload, derr := base64.RawURLEncoding.DecodeString(parts[1])
	var old auditVerifyState
	if derr != nil || json.Unmarshal(payload, &old) != nil || old.V != 1 || old.KID != t.OldKID {
		return nil, kind, why, nil
	}
	old.KeyEpoch = &auditKeyEpoch{Seq: t.Seq, Digest: t.digest()}
	return &old, "", "", nil
}

// auditKeyTransitionProblem checks the transition records against the current
// key and the state s (nil for none); a non-empty reason is a discontinuity.
func (c *KeyorixCore) auditKeyTransitionProblem(ctx context.Context, s *auditVerifyState, ev auditVerifyEvidence) (string, error) {
	recs, found, perr, err := c.loadAuditKeyTransitions(ctx)
	switch {
	case err != nil:
		return "", err
	case !found && s != nil && s.KeyEpoch != nil:
		return fmt.Sprintf("the verification state was carried over by key transition #%d, but the audit_key_transitions record is missing", s.KeyEpoch.Seq), nil
	case !found && ev.keyTransition > 0:
		return fmt.Sprintf("audit event #%d records a key transition, but the audit_key_transitions record is missing", ev.keyTransition), nil
	case !found:
		return "", nil
	case perr != nil:
		return perr.Error(), nil
	}
	kid := c.auditCkptKeyVersion
	last := recs[len(recs)-1]
	switch {
	case last.NewKID == kid:
		if !c.auditKeyTransitionNewMACValid(last) {
			return fmt.Sprintf("key transition #%d to the current key version %q fails its new-key signature (forged or altered)", last.Seq, kid), nil
		}
		if why, err := c.auditKeyTransitionHeadGone(ctx, last); err != nil || why != "" {
			return why, err
		}
	case last.OldKID == kid:
		// Pending: prepared under this key, its key files never committed.
		if !hmac.Equal([]byte(auditKeyTransitionMAC(c.auditCkptKey, "old", last.payload, "")), []byte(last.macOld)) {
			return fmt.Sprintf("pending key transition #%d from the current key version %q fails its old-key signature (forged or altered)", last.Seq, kid), nil
		}
		if n := len(recs); n > 1 && !c.auditKeyTransitionNewMACValid(recs[n-2]) {
			return fmt.Sprintf("key transition #%d to the current key version %q fails its new-key signature (forged or altered)", recs[n-2].Seq, kid), nil
		}
	default:
		return fmt.Sprintf("the latest key transition (#%d, %q to %q) is for another key epoch than the current key version %q: the key changed without carrying the audit state over", last.Seq, last.OldKID, last.NewKID, kid), nil
	}
	if s != nil && s.KeyEpoch != nil {
		if e := s.KeyEpoch; e.Seq < 1 || e.Seq > len(recs) || recs[e.Seq-1].digest() != e.Digest {
			return fmt.Sprintf("the verification state was carried over by key transition #%d, which the audit_key_transitions record no longer holds unchanged", e.Seq), nil
		}
	}
	return "", nil
}

// auditKeyTransitionHeadGone: the head a transition certified must still be in
// the chain with its hash, unless a signed retention purge removed it.
func (c *KeyorixCore) auditKeyTransitionHeadGone(ctx context.Context, t *auditKeyTransition) (string, error) {
	if t.HeadID == 0 {
		return "", nil
	}
	hash, found, err := c.storage.AuditEntryHashByID(ctx, t.HeadID)
	switch {
	case err != nil:
		return "", err
	case found && hash == t.HeadHash:
		return "", nil
	case found:
		return fmt.Sprintf("audit event #%d, the head key transition #%d certified, was rewritten", t.HeadID, t.Seq), nil
	}
	anchor, err := c.loadAuditRetentionAnchor(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to load audit chain re-anchor: %w", err)
	}
	if anchor != nil && t.HeadID < anchor.RowID {
		return "", nil
	}
	return fmt.Sprintf("audit event #%d, the head key transition #%d certified, is missing", t.HeadID, t.Seq), nil
}

// PrepareAuditKeyTransition is the first step of a key change, run by the
// command while this core still holds the OLD checkpoint key and before the
// new key files are written: it verifies everything under the old key, saves
// the verification state (recording a failed walk as a sticky failure, so a
// broken chain is carried over as broken) and appends the cross-signed record
// for newKey/newKeyVersion. A pending record from an aborted earlier attempt is
// replaced. A no-op without a checkpoint key or when the key does not change.
func (c *KeyorixCore) PrepareAuditKeyTransition(ctx context.Context, newKey []byte, newKeyVersion string) error {
	if !c.AuditCheckpointsAvailable() || newKeyVersion == c.auditCkptKeyVersion {
		return nil
	}
	if len(newKey) == 0 || newKeyVersion == "" {
		return fmt.Errorf("audit key transition: no new checkpoint key")
	}
	v, err := c.VerifyAuditChain(ctx)
	if err != nil {
		return err
	}
	if err := c.updateAuditVerifyState(ctx, func(st *auditVerifyState) *auditVerifyFailure {
		if v.Valid {
			return nil
		}
		return recordAuditVerifyFailure(st, c.now(), auditKeyTransitionSource, v.FirstBrokenID, "before key change: "+v.Reason)
	}); err != nil {
		return fmt.Errorf("audit key transition: save the verification state: %w", err)
	}
	return c.storage.WithAuditCheckpointLock(ctx, func(ctx context.Context) error {
		recs, _, perr, err := c.loadAuditKeyTransitions(ctx)
		if err != nil {
			return err
		}
		reset := ""
		if perr != nil {
			// Never block a key change (it may be the response to a compromise):
			// start a new list. The state load above recorded the damage as a
			// sticky discontinuity, and the chain's earlier transition events
			// name records the new list does not hold, so offline reads BROKEN.
			log.Printf("SECURITY: audit key transition record damaged, starting a new one: %v", perr)
			recs, reset = nil, perr.Error()
		}
		if n := len(recs); n > 0 && recs[n-1].OldKID == c.auditCkptKeyVersion {
			recs = recs[:n-1] // an aborted attempt: its key files never committed
		}
		rec, err := c.buildAuditKeyTransition(ctx, recs)
		if err != nil {
			return err
		}
		rec.Reset = reset
		rec.NewKID = newKeyVersion
		if rec.payload, err = json.Marshal(rec); err != nil {
			return err
		}
		rec.macOld = auditKeyTransitionMAC(c.auditCkptKey, "old", rec.payload, "")
		rec.macNew = auditKeyTransitionMAC(newKey, "new", rec.payload, rec.macOld)
		return c.storage.SetSystemMetadata(ctx, auditKeyTransitionsKey, encodeAuditKeyTransitions(append(recs, rec)))
	})
}

// buildAuditKeyTransition fills a record (all but the MACs) from a fresh
// walk and the stored artifacts. The caller holds WithAuditCheckpointLock.
func (c *KeyorixCore) buildAuditKeyTransition(ctx context.Context, recs []*auditKeyTransition) (*auditKeyTransition, error) {
	v, err := c.VerifyAuditChain(ctx)
	if err != nil {
		return nil, err
	}
	anchor, err := c.loadAuditRetentionAnchor(ctx)
	if err != nil {
		return nil, err
	}
	rec := &auditKeyTransition{V: 1, Seq: len(recs) + 1, OldKID: c.auditCkptKeyVersion, At: c.now().UTC(),
		HeadID: v.HeadID, HeadHash: v.HeadHash, Certified: v.ChainedEvents + anchorPurgedEvents(anchor),
		ChainValid: v.Valid, Reason: v.Reason}
	if len(recs) > 0 {
		rec.Prev = recs[len(recs)-1].digest()
	}
	for key, dst := range map[string]*string{auditVerifyStateKey: &rec.State, auditHighWaterKey: &rec.HighWater, auditRetentionAnchorKey: &rec.Anchor} {
		val, _, err := c.storage.GetSystemMetadata(ctx, key)
		if err != nil {
			return nil, err
		}
		*dst = auditDigest(val)
	}
	cp, err := c.storage.LatestAuditCheckpoint(ctx)
	if err != nil {
		return nil, err
	}
	if cp != nil {
		rec.CheckpointID, rec.Checkpoint = cp.ID, auditCheckpointDigest(cp)
	}
	return rec, nil
}

// CompleteAuditKeyTransition is the second step, run with the NEW key: by the
// command right after the key files commit, and at every server start before
// the schedulers (a crash in between is completed there). Each step is
// idempotent and the in-chain event comes last, after the state save, so a
// retry after a crash at any point finishes the job. It returns whether anything was done. An error
// means the record or the state cannot be trusted; nothing is re-signed then,
// and the state load reports the discontinuity.
func (c *KeyorixCore) CompleteAuditKeyTransition(ctx context.Context) (bool, error) {
	if !c.AuditCheckpointsAvailable() {
		return false, nil
	}
	var done bool
	var saved *auditVerifyState
	var failed *auditVerifyFailure
	err := c.storage.WithAuditCheckpointLock(ctx, func(ctx context.Context) error {
		recs, found, perr, err := c.loadAuditKeyTransitions(ctx)
		if err != nil || !found {
			return err
		}
		if perr != nil {
			return perr
		}
		t := recs[len(recs)-1]
		if t.NewKID != c.auditCkptKeyVersion {
			return nil
		}
		if !c.auditKeyTransitionNewMACValid(t) {
			return fmt.Errorf("key transition #%d to key version %q fails its new-key signature: not completed", t.Seq, t.NewKID)
		}
		stateVal, _, err := c.storage.GetSystemMetadata(ctx, auditVerifyStateKey)
		if err != nil {
			return err
		}
		st, _, why, err := c.decodeAuditVerifyStateCarried(ctx, stateVal)
		if err != nil {
			return err
		}
		if t.State != "" && (st == nil || st.KeyEpoch == nil || st.KeyEpoch.Seq != t.Seq) {
			return fmt.Errorf("key transition #%d: the verification state changed after the transition was prepared (%s): not completed", t.Seq, why)
		}
		for _, s := range []struct {
			name string
			run  func(context.Context, *auditKeyTransition) (bool, error)
		}{
			{aktStepAnchor, c.resignCarriedRetentionAnchor},
			{aktStepHighWater, c.resignCarriedHighWater},
		} {
			did, err := s.run(ctx, t)
			if err != nil {
				return fmt.Errorf("key transition #%d (%s): %w", t.Seq, s.name, err)
			}
			done = done || did
			if err := c.aktHook(s.name); err != nil {
				return err
			}
		}
		did, refusal, err := c.writeCarriedCheckpoint(ctx, t)
		if err != nil {
			return err
		}
		done = done || did
		if err := c.aktHook(aktStepCheckpoint); err != nil {
			return err
		}
		// The state save comes before the event: the event is what tells a crash
		// before this save from an old row put back after it.
		if s, _, _ := c.decodeAuditVerifyState(stateVal); st != nil && (s == nil || refusal != "") {
			st.Gen = max(st.Gen, c.auditVerifyGenSeen.Load()) + 1
			if refusal != "" {
				failed = recordAuditVerifyFailure(st, c.now(), auditKeyTransitionSource, nil, refusal)
			}
			if err := c.saveAuditVerifyState(ctx, st); err != nil {
				return err
			}
			saved, done = st, true
		}
		if err := c.aktHook(aktStepState); err != nil {
			return err
		}
		did, err = c.recordAuditKeyTransitionEvent(ctx, t)
		if err != nil {
			return fmt.Errorf("key transition #%d (%s): %w", t.Seq, aktStepEvent, err)
		}
		done = done || did
		return nil
	})
	if err != nil {
		return false, err
	}
	c.reportAuditVerifyStateEvents(ctx, saved, nil, failed)
	if done {
		log.Printf("audit key transition to key version %q completed: the verification state, high-water mark and retention anchor are signed under the new key", c.auditCkptKeyVersion)
	}
	return done, nil
}

func (c *KeyorixCore) aktHook(step string) error {
	if c.auditKeyTransitionHook == nil {
		return nil
	}
	return c.auditKeyTransitionHook(step)
}

// resignCarriedRetentionAnchor re-signs the anchor the record names under the
// current key (same row and purged count). One that already authenticates, or
// differs from the recorded digest, is left alone.
func (c *KeyorixCore) resignCarriedRetentionAnchor(ctx context.Context, t *auditKeyTransition) (bool, error) {
	val, ok, err := c.storage.GetSystemMetadata(ctx, auditRetentionAnchorKey)
	if err != nil || !ok || auditDigest(val) != t.Anchor {
		return false, err
	}
	a, parsed := parseAuditRetentionAnchor(val)
	if !parsed || a.keyVersion != t.OldKID {
		return false, nil
	}
	if err := c.persistAuditRetentionAnchor(ctx, c.storage, a.rowID, a.prevHash, a.entryHash, a.purged); err != nil {
		return false, err
	}
	return true, nil
}

// resignCarriedHighWater re-signs the high-water mark the record names under
// the current key (same count and head).
func (c *KeyorixCore) resignCarriedHighWater(ctx context.Context, t *auditKeyTransition) (bool, error) {
	val, ok, err := c.storage.GetSystemMetadata(ctx, auditHighWaterKey)
	if err != nil || !ok || auditDigest(val) != t.HighWater {
		return false, err
	}
	hw, _, parsed := parseAuditHighWater(val)
	if !parsed || hw.KeyVersion != t.OldKID {
		return false, nil
	}
	hw.KeyVersion = c.auditCkptKeyVersion
	if err := c.storage.SetSystemMetadata(ctx, auditHighWaterKey, auditHighWaterValue(hw, c.signCheckpoint(hw))); err != nil {
		return false, err
	}
	c.bumpWatermark(hw.ChainedEvents)
	return true, nil
}

func auditKeyTransitionEventText(t *auditKeyTransition) string {
	return fmt.Sprintf("audit key transition #%d: checkpoint key version %s replaced by %s; the verification state was carried over under both keys (record %s)",
		t.Seq, t.OldKID, t.NewKID, t.digest())
}

// auditKeyTransitionEventExists reports whether the in-chain event of t
// (appended last by completion) exists.
func (c *KeyorixCore) auditKeyTransitionEventExists(ctx context.Context, t *auditKeyTransition) (bool, error) {
	evs, _, err := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{
		Actions: []string{auditKeyTransitionEvent}, PageSize: 50, Count: storage.AuditCountNone,
	})
	if err != nil {
		return false, err
	}
	for _, e := range evs {
		if strings.Contains(e.Description, t.digest()) {
			return true, nil
		}
	}
	return false, nil
}

// recordAuditKeyTransitionEvent appends the in-chain record once.
func (c *KeyorixCore) recordAuditKeyTransitionEvent(ctx context.Context, t *auditKeyTransition) (bool, error) {
	if exists, err := c.auditKeyTransitionEventExists(ctx, t); err != nil || exists {
		return false, err
	}
	if !c.writeAuditEventFull(ctx, auditKeyTransitionEvent, nil, nil, nil, "", auditKeyTransitionEventText(t)) {
		return false, fmt.Errorf("the in-chain key transition event could not be appended")
	}
	return true, nil
}

// writeCarriedCheckpoint writes the fresh checkpoint under the new key when the
// chain verified at prepare and the latest checkpoint is not already signed
// under it. A refusal (the carried pin or floor proves a truncation) is
// returned as its reason: the state records it as a failure.
func (c *KeyorixCore) writeCarriedCheckpoint(ctx context.Context, t *auditKeyTransition) (done bool, refusal string, err error) {
	if !t.ChainValid {
		return false, "", nil
	}
	cp, err := c.storage.LatestAuditCheckpoint(ctx)
	if err != nil {
		return false, "", err
	}
	if cp != nil && c.checkpointSignatureValid(cp) {
		return false, "", nil
	}
	if _, err := c.writeAuditCheckpointLocked(ctx); err != nil {
		if errors.Is(err, ErrAuditCheckpointRefused) {
			return false, "after key change: " + err.Error(), nil
		}
		return false, "", err
	}
	return true, "", nil
}

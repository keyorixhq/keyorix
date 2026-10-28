// audit_verify_state.go — the signed, persisted state of incremental audit-chain
// verification (docs/specs/audit-incremental-verification.md §3).
//
// One system_metadata row holds the rolling full re-walk cycle, the last
// completed full verification, the last scheduler tail check, a sticky failure
// and the latest ?full=true job. It is HMAC-signed with the checkpoint signing
// key (KEK-derived, never in the database) under its own domain-separation
// prefix, so a DB-level actor cannot forge "verified" claims, skip segments or
// clear a failure by editing it. A row that is malformed or fails its signature
// is ignored: that can only remove claims (the API then reports not_proven),
// never add them.
//
// A signature alone does not stop an actor with DB write access from putting
// back an OLDER signed row (a replay or rollback) to resume a rolling cycle past
// a row tampered with since, or to erase a recorded failure. Each saved row
// therefore carries a generation (strictly increasing: every save happens under
// WithAuditCheckpointLock) and is bound to the latest checkpoint id and the
// signed high-water count at save time. A row older than the signed checkpoint
// trail, or than a generation this process already saw, is not trusted either.
// A writer that finds an untrusted row does not overwrite it silently: it starts
// over, records the rejection in the new signed row (reported as not_proven until
// a full verification that started after it completes) and appends a
// system.audit_verification_state_rejected event.
//
// A row that is deleted, garbled, signed under another key epoch, claims rows
// past the chain head, or predates a break the chain records cannot be continued
// at all (AUDIT-VERIFY-STATE-1): it carried the pin and sticky failure that prove
// rows were lost, so starting over would erase that evidence. Such a row raises
// a sticky discontinuity instead (auditVerifyDiscontinuity): status broken with
// its own reason, the failure gauge, a SECURITY log line and an in-chain
// system.audit_verification_state_discontinuity event. No verification clears
// it. A deleted row is told from an honest first start by the in-chain
// system.audit_verification_state_initialized marker every state keeps alive.
// Each failure event names the generation that recorded it, so a row that
// carries some failure still predates a break when any other failure event
// lies above its audit head.
// A row without an audit head (signed by an older binary) cannot be placed
// against the chain: once that marker or a discontinuity exists it can only be
// an older row put back, and is a discontinuity too (auditVerifyStateUnplaced).
package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// In-chain events about the state row. The marker exists while a state does
// (re-appended when retention purged it); the other two are breaks a row saved
// before them cannot have seen.
const (
	auditVerifyStateMarkerEvent        = "system.audit_verification_state_initialized"
	auditVerifyStateDiscontinuityEvent = "system.audit_verification_state_discontinuity"
	auditChainVerificationFailedEvent  = "system.audit_chain_verification_failed"
)

// Discontinuity kinds (each also appears in the reported reason).
const (
	auditDiscDeleted     = "deleted"
	auditDiscGarbled     = "garbled"
	auditDiscOtherEpoch  = "other key epoch"
	auditDiscPastHead    = "past the chain head"
	auditDiscBeforeBreak = "before a recorded break"
	// A key transition record missing, forged or for another key epoch
	// (audit_key_transition.go).
	auditDiscKeyTransition = "key transition"
)

// auditVerifyEvidencePage bounds one evidence-scan read; auditVerifyEvidenceRescan
// re-reads that many ids below the previous bound, for an event whose id was
// taken before the bound but committed after the previous scan.
const (
	auditVerifyEvidencePage   = 1000
	auditVerifyEvidenceRescan = 1024
)

// auditVerifyStateKey is the system_metadata key of the signed state row.
const auditVerifyStateKey = "audit_verification_state" // #nosec G101 -- metadata key name, not a credential

// auditVerifyStateSep separates the stored fields (\x1f, as the high-water mark
// and the retention anchor: PostgreSQL text rejects NUL).
const auditVerifyStateSep = "\x1f"

// auditVerifyStateDomain prefixes the signed bytes so this HMAC can never verify
// as a checkpoint, high-water or retention-anchor signature (all share the key).
const auditVerifyStateDomain = "auditverify-state-v1\x00"

// Full-verification sources recorded in auditFullResult.Source.
const (
	auditFullSourceRolling    = "rolling"
	auditFullSourceJob        = "job"
	auditFullSourceCheckpoint = "checkpoint-full"
)

// auditVerifyCycle is a rolling full re-walk in progress.
type auditVerifyCycle struct {
	StartedAt time.Time `json:"started_at"`
	// StartedGen is the state generation the cycle was started from: a failure
	// or rejection recorded at or before it existed when the walk began.
	StartedGen uint64 `json:"started_gen"`
	TargetID   uint   `json:"target_id"`
	TargetHash string `json:"target_hash"`
	// SeedID/SeedHash: the last row verified so far (0 = chain start next).
	SeedID   uint   `json:"seed_id"`
	SeedHash string `json:"seed_hash"`
	// ScannedThrough is the id bound the previous segments covered.
	ScannedThrough uint `json:"scanned_through"`
	Width          uint `json:"width"`
	// UnchainedEvents is the legacy prefix the chain-start segment counted.
	UnchainedEvents int64 `json:"unchained_events"`
}

// auditFullResult is a completed full verification (rolling cycle, full job, or
// the checkpoint write's full-walk fallback).
type auditFullResult struct {
	StartedAt       time.Time `json:"started_at"`
	CompletedAt     time.Time `json:"completed_at"`
	ThroughID       uint      `json:"through_id"`
	Source          string    `json:"source"`
	Valid           bool      `json:"valid"`
	FirstBrokenID   *uint     `json:"first_broken_id,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	UnchainedEvents int64     `json:"unchained_events"`
}

// auditTailCheck is the last scheduler tail check.
type auditTailCheck struct {
	At              time.Time `json:"at"`
	Valid           bool      `json:"valid"`
	CheckpointID    uint      `json:"checkpoint_id"`
	FromID          uint      `json:"from_id"`
	ThroughID       uint      `json:"through_id"`
	HeadHash        string    `json:"head_hash"`
	CertifiedEvents int64     `json:"certified_events"`
	ChainedEvents   int64     `json:"chained_events"`
	Checkpointed    bool      `json:"checkpointed"`
	FirstBrokenID   *uint     `json:"first_broken_id,omitempty"`
	Reason          string    `json:"reason,omitempty"`
}

// auditVerifyFailure is a detected break; sticky until a passing full
// verification clears it.
type auditVerifyFailure struct {
	DetectedAt time.Time `json:"detected_at"`
	// Gen is the generation of the save that recorded it. Only a full
	// verification that started after it may clear it (auditFailureCoveredBy).
	Gen           uint64 `json:"gen"`
	Source        string `json:"source"`
	FirstBrokenID *uint  `json:"first_broken_id,omitempty"`
	Reason        string `json:"reason"`
}

// auditVerifyJob is the latest ?full=true background job.
type auditVerifyJob struct {
	ID         string             `json:"id"`
	State      string             `json:"state"` // running | succeeded | failed
	StartedAt  time.Time          `json:"started_at"`
	StartedGen uint64             `json:"started_gen"`
	FinishedAt *time.Time         `json:"finished_at,omitempty"`
	Error      string             `json:"error,omitempty"`
	Result     *AuditVerifyReport `json:"result,omitempty"`
}

// auditVerifyBinding is the signed checkpoint trail a state row was saved
// against. Both only grow: every checkpoint write saves the state in the same
// WithAuditCheckpointLock section, after the checkpoint and the high-water mark.
type auditVerifyBinding struct {
	CheckpointID uint  `json:"checkpoint_id"`
	HighWater    int64 `json:"high_water"`
}

// auditVerifyRejection records that a writer found the persisted state
// untrusted and started over. It keeps the status not_proven until a full
// verification that started after it (Gen) completes valid.
type auditVerifyRejection struct {
	At     time.Time `json:"at"`
	Gen    uint64    `json:"gen"`
	Reason string    `json:"reason"`
}

// auditVerifyPin is the newest snapshot a checkpoint write certified under the
// key that signs the row (chained + purged units, the certified head). Saves
// never lower it while the row stays authentic, so it survives a relabelled or
// deleted checkpoint and high-water mark: the write paths refuse to re-baseline
// a chain it proves was truncated (auditVerifyStateTruncation). A key change
// makes the row fail its signature, which drops the pin with everything else.
type auditVerifyPin struct {
	Events   int64  `json:"events"`
	HeadID   uint   `json:"head_id"`
	HeadHash string `json:"head_hash"`
}

// auditVerifyDiscontinuity records that the persisted state could not be
// continued (see the package comment). Sticky: no verification clears it; only
// accepting a proven loss of rows (`admin audit accept-loss`, audit_seal.go)
// moves it to the state's accepted list.
type auditVerifyDiscontinuity struct {
	DetectedAt time.Time `json:"detected_at"`
	Kind       string    `json:"kind"`
	Reason     string    `json:"reason"`
}

// auditVerifyState is the whole signed row.
type auditVerifyState struct {
	V int `json:"v"`
	// KID is the key version the row was signed under. It is read unauthenticated
	// only to name a signature failure (another key epoch or garbled); both are
	// discontinuities.
	KID string `json:"kid,omitempty"`
	// Gen is strictly increasing across saves; Bind is the trail at save time.
	Gen  uint64             `json:"gen"`
	Bind auditVerifyBinding `json:"bind"`
	// AuditHead is the highest audit event id at save time: a row may not claim
	// rows past the head, nor predate a break event after it while lacking that
	// break. Placed is set on every row this binary saves, so AuditHead 0 on a
	// placed row means the chain was empty, never "unknown". An unplaced row was
	// signed by a binary from before AUDIT-VERIFY-STATE-1 (or re-signed by one,
	// which drops these fields and Discontinuity): see auditVerifyStateUnplaced.
	AuditHead     uint                      `json:"audit_head,omitempty"`
	Placed        bool                      `json:"placed,omitempty"`
	Pin           *auditVerifyPin           `json:"pin,omitempty"`
	Rejected      *auditVerifyRejection     `json:"rejected,omitempty"`
	Discontinuity *auditVerifyDiscontinuity `json:"discontinuity,omitempty"`
	// KeyEpoch names the key transition that carried this state over to the
	// key that signs it (audit_key_transition.go); nil before any.
	KeyEpoch *auditKeyEpoch `json:"key_epoch,omitempty"`
	// Seals is the number of accepted losses (audit_seal.go) when the row was
	// saved; it must equal the seal record's count. Accepted lists what the
	// acceptances cleared (a discontinuity, a failure, the walk's break).
	Seals     int                 `json:"seals,omitempty"`
	Accepted  []AuditSealAccepted `json:"accepted,omitempty"`
	Cycle     *auditVerifyCycle   `json:"cycle,omitempty"`
	LastFull  *auditFullResult    `json:"last_full,omitempty"`
	LastCheck *auditTailCheck     `json:"last_check,omitempty"`
	Failure   *auditVerifyFailure `json:"failure,omitempty"`
	Job       *auditVerifyJob     `json:"job,omitempty"`

	// detected is a discontinuity found by the load this state came from; a
	// writer reports it (event, log, counter) after saving. needMarker: the save
	// found no live in-chain marker. Neither is persisted.
	detected   *auditVerifyDiscontinuity
	needMarker bool
}

// claimedThrough is the highest audit event id the row says existed.
func (s *auditVerifyState) claimedThrough() uint {
	n := s.AuditHead
	if s.Pin != nil {
		n = max(n, s.Pin.HeadID)
	}
	if s.LastCheck != nil {
		n = max(n, s.LastCheck.ThroughID)
	}
	if s.LastFull != nil {
		n = max(n, s.LastFull.ThroughID)
	}
	if s.Cycle != nil {
		n = max(n, s.Cycle.TargetID, s.Cycle.SeedID)
	}
	return n
}

// auditVerifyEvidence is what the chain says about state rows: the newest id of
// each event type above (0 = none seen) and the head id. A failure event names
// the state generation whose save recorded it (auditFailureEventGen, 0 = none:
// an older binary's text); failureGen is that of the newest failure event,
// failureOther the newest failure event another generation recorded, and
// maxFailureGen the highest generation any failure event names.
type auditVerifyEvidence struct {
	head, marker, failure, discontinuity, keyTransition uint
	failureGen                                          uint64
	failureOther                                        uint
	maxFailureGen                                       uint64
	// seal is the newest system.audit_loss_accepted event; sealNamed maps the
	// seal record digest each such event names to its id (audit_seal.go).
	seal      uint
	sealNamed map[string]uint
}

// noteSeal adds one accepted-loss event.
func (ev *auditVerifyEvidence) noteSeal(id uint, description string) {
	ev.seal = max(ev.seal, id)
	m := auditSealEventDigestRE.FindStringSubmatch(description)
	if m == nil {
		return
	}
	if ev.sealNamed == nil {
		ev.sealNamed = map[string]uint{}
	}
	ev.sealNamed[m[1]] = max(ev.sealNamed[m[1]], id)
}

// noteFailure adds one failure event. The result does not depend on the order
// events are added in or on repeats (the scan re-reads a window).
func (ev *auditVerifyEvidence) noteFailure(id uint, gen uint64) {
	other := gen != ev.failureGen
	switch {
	case id > ev.failure:
		if other {
			ev.failureOther = ev.failure
		}
		ev.failure, ev.failureGen = id, gen
	case id < ev.failure && other:
		ev.failureOther = max(ev.failureOther, id)
	}
	ev.maxFailureGen = max(ev.maxFailureGen, gen)
}

// foreignFailure is the newest failure event id that state generation own did
// not record (own 0: any failure event, so an event naming no generation is
// never a row's own), 0 when there is none.
func (ev auditVerifyEvidence) foreignFailure(own uint64) uint {
	if own != 0 && ev.failureGen == own {
		return ev.failureOther
	}
	return ev.failure
}

// auditFailureEventText is the description of the failure event for f. It names
// the generation of the save that recorded f, so the load can tell a row's own
// failure event (appended after that save, so above its audit head) from a
// failure the row never saw.
func auditFailureEventText(f *auditVerifyFailure) string {
	return fmt.Sprintf("audit chain verification failed (%s, state generation %d): %s", f.Source, f.Gen, f.Reason)
}

var auditFailureEventGenRE = regexp.MustCompile(`^audit chain verification failed \([a-z-]+, state generation ([1-9][0-9]{0,17})\): `)

// auditFailureEventGen is the generation a failure event's description names
// (auditFailureEventText), or 0 when it names none.
func auditFailureEventGen(description string) uint64 {
	m := auditFailureEventGenRE.FindStringSubmatch(description)
	if m == nil {
		return 0
	}
	gen, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		return 0
	}
	return gen
}

// auditVerifyEvidenceIndex caches auditVerifyEvidence per process, so each scan
// reads only the ids appended since the last one.
type auditVerifyEvidenceIndex struct {
	mu      sync.Mutex
	through uint
	ev      auditVerifyEvidence
}

// scanAuditVerifyEvidence brings the evidence up to the current head. The first
// call in a process reads the whole table (filtered by event type, the matches
// are rare); later calls read only what was appended since.
func (c *KeyorixCore) scanAuditVerifyEvidence(ctx context.Context) (auditVerifyEvidence, error) {
	idx := &c.auditVerifyEvidence
	idx.mu.Lock()
	defer idx.mu.Unlock()
	head, err := c.storage.MaxAuditEventID(ctx)
	if err != nil {
		return auditVerifyEvidence{}, err
	}
	after := idx.through - min(idx.through, auditVerifyEvidenceRescan)
	for after < head {
		from := after
		evs, _, err := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{
			Actions:   []string{auditVerifyStateMarkerEvent, auditChainVerificationFailedEvent, auditVerifyStateDiscontinuityEvent, auditKeyTransitionEvent, auditSealEvent},
			AfterID:   &from,
			UpToID:    &head,
			Ascending: true,
			PageSize:  auditVerifyEvidencePage,
			Count:     storage.AuditCountNone,
		})
		if err != nil {
			return auditVerifyEvidence{}, fmt.Errorf("failed to read audit verification evidence: %w", err)
		}
		if len(evs) == 0 {
			break
		}
		for _, e := range evs {
			switch e.EventType {
			case auditVerifyStateMarkerEvent:
				idx.ev.marker = max(idx.ev.marker, e.ID)
			case auditChainVerificationFailedEvent:
				idx.ev.noteFailure(e.ID, auditFailureEventGen(e.Description))
			case auditVerifyStateDiscontinuityEvent:
				idx.ev.discontinuity = max(idx.ev.discontinuity, e.ID)
			case auditKeyTransitionEvent:
				idx.ev.keyTransition = max(idx.ev.keyTransition, e.ID)
			case auditSealEvent:
				idx.ev.noteSeal(e.ID, e.Description)
			}
			after = max(after, e.ID)
		}
	}
	idx.through = max(idx.through, head)
	idx.ev.head = head
	ev := idx.ev
	ev.sealNamed = maps.Clone(idx.ev.sealNamed)
	return ev, nil
}

// discontinuedAuditVerifyState is the state a load returns for a row that cannot
// be continued. prev is the row when it authenticated (its generation, pin,
// failure, job and an earlier discontinuity are kept: they only make the verdict
// stricter); nil when it was deleted or does not authenticate.
func (c *KeyorixCore) discontinuedAuditVerifyState(prev *auditVerifyState, kind, reason string) *auditVerifyState {
	d := &auditVerifyDiscontinuity{DetectedAt: c.now(), Kind: kind, Reason: reason}
	st := &auditVerifyState{V: 1, Discontinuity: d, detected: d}
	if prev != nil {
		st.Gen, st.Pin, st.Failure, st.Job, st.KeyEpoch = prev.Gen, prev.Pin, prev.Failure, prev.Job, prev.KeyEpoch
		st.Seals, st.Accepted = prev.Seals, prev.Accepted
		if prev.Discontinuity != nil {
			st.Discontinuity = prev.Discontinuity
		}
	}
	return st
}

// auditDiscontinuityText is the reported reason of a discontinuity.
func auditDiscontinuityText(d *auditVerifyDiscontinuity) string {
	return fmt.Sprintf("audit verification state discontinuity (%s) detected at %s: %s. Continuity with every earlier verification is lost: rows removed or altered before this point may no longer be detectable. This alarm is sticky; no verification clears it (docs/operator/audit-chain-break-runbook.md)",
		d.Kind, d.DetectedAt.UTC().Format(time.RFC3339), d.Reason)
}

func (c *KeyorixCore) signAuditVerifyState(payload []byte) string {
	mac := hmac.New(sha256.New, c.auditCkptKey)
	mac.Write([]byte(auditVerifyStateDomain))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// currentAuditVerifyBinding reads the signed checkpoint trail a state row must
// not be older than: the latest checkpoint row's id and the authenticated
// high-water count (0 when the mark is absent or does not verify, which only
// loosens the check; the tail check reports those).
func (c *KeyorixCore) currentAuditVerifyBinding(ctx context.Context) (auditVerifyBinding, error) {
	var b auditVerifyBinding
	cp, err := c.storage.LatestAuditCheckpoint(ctx)
	if err != nil {
		return b, err
	}
	if cp != nil {
		b.CheckpointID = cp.ID
	}
	hw, err := c.authenticatedHighWaterBase(ctx)
	if err != nil {
		return b, err
	}
	if hw != nil {
		b.HighWater = hw.ChainedEvents
	}
	return b, nil
}

// bumpAuditVerifyGen raises the in-process generation floor to gen.
func (c *KeyorixCore) bumpAuditVerifyGen(gen uint64) {
	for {
		seen := c.auditVerifyGenSeen.Load()
		if gen <= seen || c.auditVerifyGenSeen.CompareAndSwap(seen, gen) {
			return
		}
	}
}

// loadAuditVerifyState reads and authenticates the state row. A missing row is
// an empty state with no reason only when nothing proves one existed (a fresh
// or upgraded deployment). A row that cannot be continued — deleted, malformed,
// failing its signature, claiming rows past the chain head, or saved before a
// break the chain records — returns a state carrying a sticky Discontinuity
// (and detected set) with no reason. A row that is authentic but older than
// the signed checkpoint trail or than a generation this process saw (a replay
// or rollback) returns a non-empty reason and keeps only its generation,
// sticky failure, discontinuity and job. Only a storage failure is an error.
func (c *KeyorixCore) loadAuditVerifyState(ctx context.Context) (st *auditVerifyState, reason string, err error) {
	st, reason, err = c.loadAuditVerifyStateUnobserved(ctx)
	switch {
	case err != nil:
	case reason != "" || st.detected != nil:
		c.observeAuditVerifyStateUntrusted(st, reason != "")
	case c.AuditCheckpointsAvailable():
		c.observeAuditVerifyState(st)
	}
	return st, reason, err
}

// loadAuditVerifyStateUnobserved is loadAuditVerifyState without publishing the
// result to the audit-verify metrics.
func (c *KeyorixCore) loadAuditVerifyStateUnobserved(ctx context.Context) (st *auditVerifyState, reason string, err error) {
	if !c.AuditCheckpointsAvailable() {
		return &auditVerifyState{V: 1}, "", nil
	}
	// The checkpoint trail below is signed under the seal list (audit_seal.go).
	seals, err := c.loadAuditSeals(ctx)
	if err != nil {
		return nil, "", err
	}
	// The trail is read BEFORE the row: a writer saves the row after the
	// checkpoint it binds to, so a concurrent write can only make the row newer
	// than what was read here, never look stale.
	cur, err := c.currentAuditVerifyBinding(ctx)
	if err != nil {
		return nil, "", err
	}
	val, ok, err := c.storage.GetSystemMetadata(ctx, auditVerifyStateKey)
	if err != nil {
		return nil, "", err
	}
	// Read after the row: ids only grow, so a row saved before this read cannot
	// look past the head, and an event it predates is already visible.
	ev, err := c.scanAuditVerifyEvidence(ctx)
	if err != nil {
		return nil, "", err
	}
	seen := c.auditVerifyGenSeen.Load()
	if !ok {
		switch {
		case seen > 0:
			return c.discontinuedAuditVerifyState(nil, auditDiscDeleted,
				fmt.Sprintf("the persisted verification state is missing although this server already read generation %d", seen)), "", nil
		case ev.marker > 0 || ev.discontinuity > 0:
			return c.discontinuedAuditVerifyState(nil, auditDiscDeleted,
				fmt.Sprintf("the persisted verification state is missing although audit event #%d records that one exists", max(ev.marker, ev.discontinuity))), "", nil
		}
		if why, err := c.auditCheckpointTrailUnauthenticated(ctx); err != nil {
			return nil, "", err
		} else if why != "" {
			return c.discontinuedAuditVerifyState(nil, auditDiscDeleted,
				"the persisted verification state is missing while "+why), "", nil
		}
		return &auditVerifyState{V: 1}, "", nil
	}
	s, kind, why, err := c.decodeAuditVerifyStateCarried(ctx, val)
	if err != nil {
		return nil, "", err
	}
	if s == nil {
		return c.discontinuedAuditVerifyState(nil, kind, why), "", nil
	}
	if why := auditVerifyStateSealProblem(s, seals, ev); why != "" {
		return c.discontinuedAuditVerifyState(s, auditDiscSeal, why), "", nil
	}
	// A row that already carries a discontinuity has raised the alarm: the
	// checks below would only find the same gap again.
	if s.Discontinuity == nil {
		if claimed := s.claimedThrough(); claimed > ev.head {
			return c.discontinuedAuditVerifyState(s, auditDiscPastHead,
				fmt.Sprintf("the authentic persisted verification state covers audit event #%d, but the chain ends at #%d: rows it verified were removed", claimed, ev.head)), "", nil
		}
		if kind, why, err := c.auditVerifyStateHeadGone(ctx, s); err != nil {
			return nil, "", err
		} else if kind != "" {
			return c.discontinuedAuditVerifyState(s, kind, why), "", nil
		}
		if why, err := c.auditKeyTransitionProblem(ctx, s, ev); err != nil {
			return nil, "", err
		} else if why != "" {
			return c.discontinuedAuditVerifyState(s, auditDiscKeyTransition, why), "", nil
		}
	}
	if s.Placed {
		// AuditHead is exact, 0 included (saved on an empty chain). A failure
		// event above it was appended after the save. Only the row's own
		// failure may be among them (its event follows the recording save);
		// any other, older or newer than the row's failure, is a break the row
		// never saw. Carrying some failure is not enough.
		var own uint64
		if s.Failure != nil {
			own = s.Failure.Gen
		}
		switch {
		case ev.foreignFailure(own) > s.AuditHead:
			return c.discontinuedAuditVerifyState(s, auditDiscBeforeBreak,
				fmt.Sprintf("the persisted verification state was saved at audit event #%d without the verification failure recorded at audit event #%d (an older row put back to erase it)", s.AuditHead, ev.foreignFailure(own))), "", nil
		case s.Discontinuity == nil && ev.discontinuity > s.AuditHead:
			return c.discontinuedAuditVerifyState(s, auditDiscBeforeBreak,
				fmt.Sprintf("the persisted verification state was saved at audit event #%d without the discontinuity recorded at audit event #%d (an older row put back to erase it)", s.AuditHead, ev.discontinuity)), "", nil
		}
	} else if why := auditVerifyStateUnplaced(ev); why != "" {
		return c.discontinuedAuditVerifyState(s, auditDiscBeforeBreak, why), "", nil
	}
	untrusted := func(why string) (*auditVerifyState, string, error) {
		return &auditVerifyState{V: 1, Gen: s.Gen, Failure: s.Failure, Discontinuity: s.Discontinuity, Job: s.Job, KeyEpoch: s.KeyEpoch, Seals: s.Seals, Accepted: s.Accepted},
			"the persisted verification state " + why + " (a replayed or rolled-back row) and was ignored", nil
	}
	if s.Gen < seen {
		return untrusted(fmt.Sprintf("is generation %d, older than generation %d this server already read", s.Gen, seen))
	}
	if s.Bind.CheckpointID < cur.CheckpointID || s.Bind.HighWater < cur.HighWater {
		return untrusted(fmt.Sprintf("was saved at checkpoint #%d and high-water %d, older than the signed checkpoint #%d and high-water %d",
			s.Bind.CheckpointID, s.Bind.HighWater, cur.CheckpointID, cur.HighWater))
	}
	c.bumpAuditVerifyGen(s.Gen)
	return s, "", nil
}

// auditVerifyStateSealProblem compares an authentic state row with the seal
// record: a record that cannot be trusted, or a row saved under another number
// of seals (an older row put back over an acceptance, or a seal record deleted
// or replaced since), is a discontinuity. A row that already carries a
// discontinuity keeps it (the checks would only find the same gap again).
func auditVerifyStateSealProblem(s *auditVerifyState, seals *auditSealSet, ev auditVerifyEvidence) string {
	switch {
	case s.Discontinuity != nil:
		return ""
	case len(seals.recs) == 0 && seals.problem == "" && ev.seal > 0:
		return fmt.Sprintf("audit event #%d records an accepted loss, but the audit_seals record is missing", ev.seal)
	case seals.problem != "":
		return "the audit seal record cannot be trusted: " + seals.problem
	case s.Seals < len(seals.recs):
		return fmt.Sprintf("the persisted verification state was saved before accepted loss #%d (an older row put back over an acceptance)", s.Seals+1)
	case s.Seals > len(seals.recs):
		return fmt.Sprintf("the persisted verification state was saved after %d accepted loss(es), but the audit_seals record holds %d (the seal record was deleted or replaced)", s.Seals, len(seals.recs))
	}
	return ""
}

// auditVerifyStateUnplaced judges an authentic row without Placed, which this
// binary never writes. Only the binary from before AUDIT-VERIFY-STATE-1 signs
// such rows, and it never appends the in-chain marker or a discontinuity: once
// either exists, a row saved by this binary has been placed, so an unplaced row
// is an older row put back, or an older replica's re-sign that dropped a
// discontinuity (a mixed-version rolling upgrade). Both erase evidence, so both
// are a discontinuity. Without either event (an honest upgrade, the first load
// after it) the row is continued; the replay checks still apply. A failure
// event alone cannot place it: the older binary appends those too.
func auditVerifyStateUnplaced(ev auditVerifyEvidence) string {
	if id := max(ev.marker, ev.discontinuity); id > 0 {
		return fmt.Sprintf("the persisted verification state carries no audit head (signed by, or re-signed by, a server version from before audit event #%d recorded that the current state format is in use): an older row put back, or an older replica that dropped its fields", id)
	}
	return ""
}

// auditCheckpointTrailUnauthenticated describes a latest checkpoint or
// high-water mark that exists but fails its signature under the current key
// ("" when there is none). With no state row and no in-chain marker left (the
// chain was cut back past it), that is the remaining proof that the trail was
// certified before, under a key nothing vouches for: a relabel or an
// unrecorded key change, never an honest first start.
func (c *KeyorixCore) auditCheckpointTrailUnauthenticated(ctx context.Context) (string, error) {
	cp, err := c.storage.LatestAuditCheckpoint(ctx)
	if err != nil {
		return "", err
	}
	if cp != nil && !c.checkpointSignatureValid(cp) {
		return fmt.Sprintf("audit checkpoint #%d exists but fails its signature under the current key (claiming key version %q)", cp.ID, cp.KeyVersion), nil
	}
	val, ok, err := c.storage.GetSystemMetadata(ctx, auditHighWaterKey)
	if err != nil || !ok {
		return "", err
	}
	if hw, sig, parsed := c.parseAuditHighWaterBound(val); !parsed || !c.checkpointSigMatches(hw, sig) {
		return "the audit high-water mark exists but does not authenticate under the current key", nil
	}
	return "", nil
}

// auditVerifyStateHeadGone checks the head row an authentic state certified
// (its pin, or for a row saved before pins its last valid tail check): it
// returns a discontinuity kind and reason when that row is missing (unless a
// signed retention purge removed it) or carries another hash. Ids are never
// reused, so after new rows are appended this is what still shows the gap the
// claimedThrough comparison saw before.
func (c *KeyorixCore) auditVerifyStateHeadGone(ctx context.Context, s *auditVerifyState) (kind, reason string, err error) {
	var id uint
	var hash string
	switch {
	case s.Pin != nil && s.Pin.HeadID != 0:
		id, hash = s.Pin.HeadID, s.Pin.HeadHash
	case s.LastCheck != nil && s.LastCheck.Valid && s.LastCheck.ThroughID != 0:
		id, hash = s.LastCheck.ThroughID, s.LastCheck.HeadHash
	default:
		return "", "", nil
	}
	got, found, err := c.storage.AuditEntryHashByID(ctx, id)
	switch {
	case err != nil:
		return "", "", err
	case found && got == hash:
		return "", "", nil
	case found:
		return auditDiscPastHead, fmt.Sprintf("audit event #%d, the head the authentic persisted verification state certified, was rewritten", id), nil
	}
	anchor, err := c.loadAuditRetentionAnchor(ctx)
	if err != nil {
		return "", "", fmt.Errorf("failed to load audit chain re-anchor: %w", err)
	}
	if anchor != nil && id < anchor.RowID {
		return "", "", nil // removed by a sanctioned retention purge
	}
	return auditDiscPastHead, fmt.Sprintf("audit event #%d, the head the authentic persisted verification state certified, is missing: rows it verified were removed", id), nil
}

// decodeAuditVerifyState parses and authenticates a stored state row under the
// current key. When the row is malformed or fails its signature it returns nil,
// the discontinuity kind and the reason. It applies no replay or rollback
// check: callers that need one (loadAuditVerifyStateUnobserved) add it.
func (c *KeyorixCore) decodeAuditVerifyState(val string) (*auditVerifyState, string, string) {
	const malformed = "the persisted verification state is malformed (garbled or truncated)"
	parts := strings.Split(val, auditVerifyStateSep)
	if len(parts) != 3 || parts[0] != "avs-v1" {
		return nil, auditDiscGarbled, malformed
	}
	payload, derr := base64.RawURLEncoding.DecodeString(parts[1])
	if derr != nil {
		return nil, auditDiscGarbled, malformed
	}
	var s auditVerifyState
	jerr := json.Unmarshal(payload, &s)
	if !hmac.Equal([]byte(c.signAuditVerifyState(payload)), []byte(parts[2])) {
		// The key version is not authenticated here: it only names the failure.
		if jerr == nil && s.KID != "" && s.KID != c.auditCkptKeyVersion {
			return nil, auditDiscOtherEpoch, fmt.Sprintf("the persisted verification state fails its signature under the current key version %q and claims key version %q (a key change that did not carry the state over, or a relabelled row)", c.auditCkptKeyVersion, s.KID)
		}
		return nil, auditDiscGarbled, "the persisted verification state fails its signature under the current key (tampered, or signed under an earlier key before rows recorded their key version)"
	}
	if jerr != nil || s.V != 1 {
		return nil, auditDiscGarbled, malformed
	}
	return &s, "", ""
}

// signedAuditVerifyPin returns what the stored state row proves the chain
// reached under the CURRENT key, or nil when the row is absent, malformed or
// does not authenticate (a key change, or a row an actor garbled or deleted).
//
// It deliberately skips loadAuditVerifyState's replay and rollback checks: an
// authentic row is a valid floor even when it is older than the checkpoint
// trail. A replayed older row can only lower the floor, never raise it, while
// the replay check would let an actor discard the newest row's pin just by
// inserting a junk checkpoint row with a higher id.
//
// The pin is the row's own Pin, or, for a row saved before pins existed, its
// last valid tail check. Its count is raised to Bind.HighWater, the high-water
// count that authenticated under this key when the row was saved; that bound
// pins no head.
func (c *KeyorixCore) signedAuditVerifyPin(ctx context.Context) (*auditVerifyPin, error) {
	if !c.AuditCheckpointsAvailable() {
		return nil, nil
	}
	val, ok, err := c.storage.GetSystemMetadata(ctx, auditVerifyStateKey)
	if err != nil || !ok {
		return nil, err
	}
	s, _, _, err := c.decodeAuditVerifyStateCarried(ctx, val)
	if s == nil {
		return nil, err
	}
	// A pin certified before an accepted loss is not a floor for the chain
	// after it (accept-loss re-baselines it). Only a row saved under fewer
	// seals than the record holds is dropped: a row saved under more (a seal
	// record deleted or replaced since) keeps its pin, so deleting the record
	// cannot remove the floor a re-baseline is checked against. The state load
	// reports both as discontinuities.
	seals, err := c.loadAuditSeals(ctx)
	if err != nil {
		return nil, err
	}
	if seals.problem == "" && s.Seals < len(seals.recs) {
		return nil, nil
	}
	var pin auditVerifyPin
	switch {
	case s.Pin != nil:
		pin = *s.Pin
	case s.LastCheck != nil && s.LastCheck.Valid:
		pin = auditVerifyPin{Events: s.LastCheck.CertifiedEvents, HeadID: s.LastCheck.ThroughID, HeadHash: s.LastCheck.HeadHash}
	}
	pin.Events = max(pin.Events, s.Bind.HighWater)
	if pin.Events == 0 && pin.HeadID == 0 {
		return nil, nil
	}
	return &pin, nil
}

// auditVerifyFailureGenFloor is the highest generation a failure event the
// last evidence scan read names.
func (c *KeyorixCore) auditVerifyFailureGenFloor() uint64 {
	idx := &c.auditVerifyEvidence
	idx.mu.Lock()
	defer idx.mu.Unlock()
	return idx.ev.maxFailureGen
}

// loadAuditVerifyStateForWrite is loadAuditVerifyState for a writer holding
// WithAuditCheckpointLock. An untrusted row is not silently replaced: the
// returned state records the rejection (non-nil rejected, which the caller
// reports with an audit event after saving). st.Gen is already the generation
// the caller's save carries, so a failure or job recorded now is stamped with it.
func (c *KeyorixCore) loadAuditVerifyStateForWrite(ctx context.Context) (st *auditVerifyState, rejected *auditVerifyRejection, err error) {
	st, reason, err := c.loadAuditVerifyState(ctx)
	if err != nil {
		return nil, nil, err
	}
	// Above every generation a failure event names too: after a row was lost
	// (deleted or garbled) and the process restarted, generations would start
	// over and a new failure could reuse an old one's, which the load would
	// then take for a row's own.
	st.Gen = max(st.Gen, c.auditVerifyGenSeen.Load(), c.auditVerifyFailureGenFloor()) + 1
	if reason != "" {
		st.Rejected = &auditVerifyRejection{At: c.now(), Gen: st.Gen, Reason: reason}
		rejected = st.Rejected
	}
	return st, rejected, nil
}

// saveAuditVerifyState binds, signs and stores st (no-op without a signing
// key). The caller holds WithAuditCheckpointLock and loaded st with
// loadAuditVerifyStateForWrite.
func (c *KeyorixCore) saveAuditVerifyState(ctx context.Context, st *auditVerifyState) error {
	if !c.AuditCheckpointsAvailable() {
		return nil
	}
	bind, err := c.currentAuditVerifyBinding(ctx)
	if err != nil {
		return err
	}
	// Never lower the pin the stored row proves under this key, whatever st
	// was loaded as (an untrusted load starts from an empty state).
	prev, err := c.signedAuditVerifyPin(ctx)
	if err != nil {
		return err
	}
	if prev != nil && (st.Pin == nil || prev.Events > st.Pin.Events) {
		st.Pin = prev
	}
	head, err := c.storage.MaxAuditEventID(ctx)
	if err != nil {
		return err
	}
	if st.needMarker, err = c.auditVerifyMarkerMissing(ctx); err != nil {
		return err
	}
	st.V = 1
	st.KID = c.auditCkptKeyVersion
	if seals, err := c.loadAuditSeals(ctx); err != nil {
		return err
	} else if seals.problem == "" {
		// A row that cannot be checked against the seal record keeps its own
		// count; the load reports the discontinuity.
		st.Seals = len(seals.recs)
	}
	st.Bind = bind
	st.AuditHead = head
	st.Placed = true
	payload, err := json.Marshal(st)
	if err != nil {
		return err
	}
	val := strings.Join([]string{"avs-v1", base64.RawURLEncoding.EncodeToString(payload), c.signAuditVerifyState(payload)}, auditVerifyStateSep)
	if err := c.storage.SetSystemMetadata(ctx, auditVerifyStateKey, val); err != nil {
		return err
	}
	c.bumpAuditVerifyGen(st.Gen)
	c.observeAuditVerifyState(st)
	return nil
}

// updateAuditVerifyState is the read-modify-write every state writer uses. It
// holds WithAuditCheckpointLock (cross-replica on PostgreSQL) only for the
// merge, never for a walk. fn returns whether a failure was newly recorded,
// in which case a system.audit_chain_verification_failed event is appended
// after the save (the in-chain record that survives a state rollback).
func (c *KeyorixCore) updateAuditVerifyState(ctx context.Context, fn func(st *auditVerifyState) (newFailure *auditVerifyFailure)) error {
	var failed *auditVerifyFailure
	var rejected *auditVerifyRejection
	var saved *auditVerifyState
	err := c.storage.WithAuditCheckpointLock(ctx, func(ctx context.Context) error {
		st, rej, err := c.loadAuditVerifyStateForWrite(ctx)
		if err != nil {
			return err
		}
		rejected = rej
		failed = fn(st)
		if err := c.saveAuditVerifyState(ctx, st); err != nil {
			return err
		}
		saved = st
		return nil
	})
	if err != nil {
		return err
	}
	c.reportAuditVerifyStateEvents(ctx, saved, rejected, failed)
	return nil
}

// auditVerifyMarkerMissing reports whether the chain lacks a live marker: none
// was seen, or the newest one is gone (a retention purge took it).
func (c *KeyorixCore) auditVerifyMarkerMissing(ctx context.Context) (bool, error) {
	ev, err := c.scanAuditVerifyEvidence(ctx)
	if err != nil || ev.marker == 0 {
		return err == nil, err
	}
	_, found, err := c.storage.AuditEntryHashByID(ctx, ev.marker)
	return !found, err
}

// reportAuditVerifyStateEvents runs after a save of st (nil when nothing was
// saved): it reports a discontinuity the load detected, appends the marker the
// save found missing, and appends the in-chain records of a rejected state row
// and of a newly recorded failure.
func (c *KeyorixCore) reportAuditVerifyStateEvents(ctx context.Context, st *auditVerifyState, rejected *auditVerifyRejection, failed *auditVerifyFailure) {
	if st != nil && st.detected != nil {
		auditVerifyStateDiscontinuities.Inc()
		log.Printf("SECURITY: audit verification state discontinuity (%s): %s", st.detected.Kind, st.detected.Reason)
		c.writeAuditEventFailedFull(ctx, auditVerifyStateDiscontinuityEvent, nil, nil, nil, "",
			auditDiscontinuityText(st.detected))
	}
	if st != nil && st.needMarker {
		c.writeAuditEventFull(ctx, auditVerifyStateMarkerEvent, nil, nil, nil, "",
			"audit verification state in use: a missing verification state row is reported as a discontinuity from now on")
	}
	if rejected != nil {
		c.writeAuditEventFailedFull(ctx, "system.audit_verification_state_rejected", nil, nil, nil, "",
			"audit verification state rejected and restarted: "+rejected.Reason)
	}
	if failed != nil {
		c.writeAuditEventFailedFull(ctx, auditChainVerificationFailedEvent, nil, nil, nil, "",
			auditFailureEventText(failed))
	}
}

// recordAuditVerifyFailure sets the sticky failure unless one is already
// recorded, returning the failure only when it is new. st comes from
// loadAuditVerifyStateForWrite, so st.Gen is the recording save's generation.
func recordAuditVerifyFailure(st *auditVerifyState, now time.Time, source string, firstBroken *uint, reason string) *auditVerifyFailure {
	if st.Failure != nil {
		return nil
	}
	st.Failure = &auditVerifyFailure{DetectedAt: now, Gen: st.Gen, Source: source, FirstBrokenID: firstBroken, Reason: reason}
	return st.Failure
}

// clearAuditVerifyMarkers applies a passing full verification that started
// after state generation startedGen and verified every row through throughID.
// A failure is cleared only when it was recorded before the walk began and
// names a row the walk covered (a failure without a row id — a refusal — needs
// a full job: requireRowForFailure); a rejection only when it predates the walk.
func clearAuditVerifyMarkers(st *auditVerifyState, startedGen uint64, throughID uint, requireRowForFailure bool) {
	if f := st.Failure; f != nil && f.Gen <= startedGen {
		switch {
		case f.FirstBrokenID != nil && *f.FirstBrokenID <= throughID:
			st.Failure = nil
		case f.FirstBrokenID == nil && !requireRowForFailure:
			st.Failure = nil
		}
	}
	if r := st.Rejected; r != nil && r.Gen <= startedGen {
		st.Rejected = nil
	}
}

// audit_verify_state.go — the signed, persisted state of incremental audit-chain
// verification (docs/specs/audit-incremental-verification.md §3).
//
// One system_metadata row holds the rolling full re-walk cycle, the last
// completed full verification, the last scheduler tail check, a sticky failure
// and the latest ?full=true job. It is HMAC-signed with the checkpoint signing
// key (KEK-derived, never in the database) under its own domain-separation
// prefix, so a DB-level actor cannot forge "verified" claims, skip segments or
// clear a failure by editing it. A row that is absent, malformed or fails its
// signature is ignored: that can only remove claims (the API then reports
// not_proven), never add them.
package core

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
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
	StartedAt  time.Time `json:"started_at"`
	TargetID   uint      `json:"target_id"`
	TargetHash string    `json:"target_hash"`
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
	DetectedAt    time.Time `json:"detected_at"`
	Source        string    `json:"source"`
	FirstBrokenID *uint     `json:"first_broken_id,omitempty"`
	Reason        string    `json:"reason"`
}

// auditVerifyJob is the latest ?full=true background job.
type auditVerifyJob struct {
	ID         string             `json:"id"`
	State      string             `json:"state"` // running | succeeded | failed
	StartedAt  time.Time          `json:"started_at"`
	FinishedAt *time.Time         `json:"finished_at,omitempty"`
	Error      string             `json:"error,omitempty"`
	Result     *AuditVerifyReport `json:"result,omitempty"`
}

// auditVerifyState is the whole signed row.
type auditVerifyState struct {
	V         int                 `json:"v"`
	Cycle     *auditVerifyCycle   `json:"cycle,omitempty"`
	LastFull  *auditFullResult    `json:"last_full,omitempty"`
	LastCheck *auditTailCheck     `json:"last_check,omitempty"`
	Failure   *auditVerifyFailure `json:"failure,omitempty"`
	Job       *auditVerifyJob     `json:"job,omitempty"`
}

func (c *KeyorixCore) signAuditVerifyState(payload []byte) string {
	mac := hmac.New(sha256.New, c.auditCkptKey)
	mac.Write([]byte(auditVerifyStateDomain))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// loadAuditVerifyState reads and authenticates the state row. It returns an
// empty state and a non-empty reason when the row exists but cannot be
// trusted; a missing row is an empty state with no reason. Only a storage
// failure is an error.
func (c *KeyorixCore) loadAuditVerifyState(ctx context.Context) (st *auditVerifyState, reason string, err error) {
	if !c.AuditCheckpointsAvailable() {
		return &auditVerifyState{V: 1}, "", nil
	}
	val, ok, err := c.storage.GetSystemMetadata(ctx, auditVerifyStateKey)
	if err != nil {
		return nil, "", err
	}
	if !ok {
		return &auditVerifyState{V: 1}, "", nil
	}
	parts := strings.Split(val, auditVerifyStateSep)
	if len(parts) != 3 || parts[0] != "avs-v1" {
		return &auditVerifyState{V: 1}, "the persisted verification state is malformed and was ignored", nil
	}
	payload, derr := base64.RawURLEncoding.DecodeString(parts[1])
	if derr != nil {
		return &auditVerifyState{V: 1}, "the persisted verification state is malformed and was ignored", nil
	}
	if !hmac.Equal([]byte(c.signAuditVerifyState(payload)), []byte(parts[2])) {
		return &auditVerifyState{V: 1}, "the persisted verification state fails its signature under the current key (tampered, or written before a KEK-provider migration) and was ignored", nil
	}
	var s auditVerifyState
	if jerr := json.Unmarshal(payload, &s); jerr != nil || s.V != 1 {
		return &auditVerifyState{V: 1}, "the persisted verification state is malformed and was ignored", nil
	}
	return &s, "", nil
}

// saveAuditVerifyState signs and stores st (no-op without a signing key).
func (c *KeyorixCore) saveAuditVerifyState(ctx context.Context, st *auditVerifyState) error {
	if !c.AuditCheckpointsAvailable() {
		return nil
	}
	st.V = 1
	payload, err := json.Marshal(st)
	if err != nil {
		return err
	}
	val := strings.Join([]string{"avs-v1", base64.RawURLEncoding.EncodeToString(payload), c.signAuditVerifyState(payload)}, auditVerifyStateSep)
	return c.storage.SetSystemMetadata(ctx, auditVerifyStateKey, val)
}

// updateAuditVerifyState is the read-modify-write every state writer uses. It
// holds WithAuditCheckpointLock (cross-replica on PostgreSQL) only for the
// merge, never for a walk. fn returns whether a failure was newly recorded,
// in which case a system.audit_chain_verification_failed event is appended
// after the save (the in-chain record that survives a state rollback).
func (c *KeyorixCore) updateAuditVerifyState(ctx context.Context, fn func(st *auditVerifyState) (newFailure *auditVerifyFailure)) error {
	var failed *auditVerifyFailure
	err := c.storage.WithAuditCheckpointLock(ctx, func() error {
		st, _, err := c.loadAuditVerifyState(ctx)
		if err != nil {
			return err
		}
		failed = fn(st)
		return c.saveAuditVerifyState(ctx, st)
	})
	if err != nil {
		return err
	}
	if failed != nil {
		c.writeAuditEventFull(ctx, "system.audit_chain_verification_failed", nil, nil, nil, "",
			"audit chain verification failed ("+failed.Source+"): "+failed.Reason)
	}
	return nil
}

// recordAuditVerifyFailure sets the sticky failure unless one is already
// recorded, returning the failure only when it is new.
func recordAuditVerifyFailure(st *auditVerifyState, now time.Time, source string, firstBroken *uint, reason string) *auditVerifyFailure {
	if st.Failure != nil {
		return nil
	}
	st.Failure = &auditVerifyFailure{DetectedAt: now, Source: source, FirstBrokenID: firstBroken, Reason: reason}
	return st.Failure
}

package storage

import (
	"time"
)

type AuditFilter struct {
	ProjectID *uint
	UserID    *uint
	// SecretID restricts to events about a specific secret (secret_node_id).
	SecretID *uint
	Action   *string
	// Actions matches any of several event types (event_type IN). Used to pull a
	// related family of events together, e.g. the RBAC audit log (role.*).
	Actions  []string
	Resource *string
	Success  *bool
	// ActorType filters by acting-principal kind: "user" or "machine_identity"
	// (also "system"). Nil = all actor types. (ADR-023)
	ActorType *string
	StartTime *time.Time
	EndTime   *time.Time
	Page      int
	PageSize  int

	// Cursor pagination for incremental SIEM export. When AfterID is set the
	// query returns events with id > *AfterID in ascending id order (a stable
	// forward cursor), ignoring Page. Use with the /audit/export endpoint.
	AfterID   *uint
	Ascending bool
	// UpToID, when set, adds id <= *UpToID (inclusive upper bound). With AfterID
	// it bounds the scan to the primary-key range (AfterID, UpToID].
	UpToID *uint

	// IPAddress filters events by the exact IP address that originated the request.
	IPAddress *string
	// RequestID filters events by the exact server-minted request id
	// (audit_events.request_id). It is advisory and not covered by the hash chain
	// (docs/specs/audit-request-id.md §5); the column is unindexed, so pair it
	// with a time window.
	RequestID *string
	// ActorUsername filters events by a partial match on the actor's username
	// (resolved via a LEFT JOIN on the users table). Nil = no username filter.
	ActorUsername *string
	// ResourceType filters events by the resource type embedded in the event_type
	// (the prefix before the first dot, e.g. "secret" from "secret.read").
	ResourceType *string

	// Before is the keyset cursor of the newest-first order (event_time DESC,
	// id DESC): only rows strictly after that position are returned and Page is
	// ignored. Ignored in Ascending mode. See docs/specs/audit-list-keyset.md.
	Before *AuditCursor
	// Count selects how the total is computed. The zero value is the exact
	// COUNT(*) over every match; a caller that discards the total passes
	// AuditCountNone, and the public list views pass AuditCountCapped.
	Count AuditCountMode
}

// AuditCursor is a position in the newest-first audit order: the event_time
// and id of the last row a page returned.
type AuditCursor struct {
	EventTime time.Time
	ID        uint
}

// AuditCountMode selects how GetAuditLogs computes its total.
type AuditCountMode int

const (
	// AuditCountExact counts every matching row (the default).
	AuditCountExact AuditCountMode = iota
	// AuditCountNone skips the count; the returned total is 0.
	AuditCountNone
	// AuditCountCapped counts at most AuditCountCap+1 matching rows, so the cost
	// is bounded by the cap rather than by the table. A total above
	// AuditCountCap means "more than AuditCountCap".
	AuditCountCapped
)

// AuditCountCap bounds AuditCountCapped. It equals the deepest offset the
// public list views let a caller reach by page number (AuditOffsetCap in
// internal/core), so a capped total still yields every reachable page.
const AuditCountCap = 10_000

// The "last user activity" lookups (LastUser*Activity) look back over the
// recertification period, not over the whole audit log: "no activity" means "no
// activity within the last N days". N defaults to the review cadence and is never
// more than ActivityLookbackMaxDays, whatever the caller asks for.
const (
	// ActivityLookbackDefaultDays is the window when no review period is configured
	// (a quarter, the default recertification cadence).
	ActivityLookbackDefaultDays = 90
	// ActivityLookbackMaxDays is the hard maximum: a year plus a day of slack.
	ActivityLookbackMaxDays = 366
)

// ActivityLookbackDays clamps a configured review period (days) to the window the
// activity lookups use: <= 0 means the default, and anything above the maximum is
// cut to it.
func ActivityLookbackDays(days int) int {
	switch {
	case days <= 0:
		return ActivityLookbackDefaultDays
	case days > ActivityLookbackMaxDays:
		return ActivityLookbackMaxDays
	}
	return days
}

// ActivityLookbackSince is the oldest event time a lookup run at now may return
// for a window of `days` days (see ActivityLookbackDays). The bound is inclusive:
// an event exactly at the returned instant is inside the window.
func ActivityLookbackSince(now time.Time, days int) time.Time {
	return now.UTC().AddDate(0, 0, -ActivityLookbackDays(days))
}

// ClampActivitySince enforces the hard maximum on a caller-supplied `since`: a
// zero or older-than-maximum value is raised to the maximum lookback, so no caller
// can ask a lookup to scan more of the audit log than the maximum window.
func ClampActivitySince(now, since time.Time) time.Time {
	floor := ActivityLookbackSince(now, ActivityLookbackMaxDays)
	if since.IsZero() || since.Before(floor) {
		return floor
	}
	return since.UTC()
}

// AuditRetentionStats holds the raw aggregates backing the audit-retention
// coverage report: how many audit events exist and the timestamps of the
// oldest and newest. Oldest/Newest are nil when the audit table is empty.
type AuditRetentionStats struct {
	TotalEvents int64
	Oldest      *time.Time
	Newest      *time.Time
}

// AuditChainVerification is the verdict of re-walking the audit hash chain
// (ADR-029). Valid is true when every chained event's hash and linkage check
// out. On failure, FirstBrokenID and Reason identify the first divergence.
type AuditChainVerification struct {
	// Valid is true when the chained suffix is intact end to end.
	Valid bool
	// ChainedEvents is the number of hash-chained events verified.
	ChainedEvents int64
	// UnchainedEvents is the leading run of legacy rows (pre-ADR-029, empty
	// hashes) skipped before the chain begins.
	UnchainedEvents int64
	// FirstBrokenID is the id of the first event that failed verification, nil
	// when Valid.
	FirstBrokenID *uint
	// Reason is a human-readable description of the first failure, empty when
	// Valid.
	Reason string
	// HeadHash is the entry_hash of the last chained event (the chain head),
	// genesis when there are no chained events. HeadID is its id. Surfaced so an
	// external monitor can record (ChainedEvents, HeadHash) and detect tail-
	// truncation or a genesis re-seed — which an unanchored on-box re-walk cannot
	// catch on its own (ADR-029): a shorter-but-self-consistent chain still
	// verifies, so the count dropping or the head changing for a known prefix is
	// the off-box tamper signal.
	HeadHash string
	HeadID   uint

	// Checkpointed is true when the live chain was additionally verified against
	// a signed in-DB checkpoint (ADR-029) — an on-box anchor a DBA cannot forge.
	// When a valid checkpoint exists and the chain has dropped below it (or the
	// checkpointed head changed), Valid is false and CheckpointReason explains it.
	// CheckpointReason also carries non-fatal notes (e.g. a checkpoint signed
	// under a superseded key version, which is recorded but not enforced).
	Checkpointed     bool
	CheckpointReason string

	// AnchorToken/AnchoredAt/AnchorProvider surface the latest checkpoint's raw
	// external-notary (RFC 3161) receipt (ADR-029), when one exists — regardless of
	// whether this server was able to (re-)verify it locally (i.e. even without a
	// configured trust root, or when local re-verification fails). Handing back the
	// opaque token lets an operator or an independent monitor verify it themselves
	// against the TSA out-of-band, without having to trust this server's own
	// verification of it — the point of an external anchor in the first place.
	// Empty when checkpoints are unavailable, no checkpoint exists yet, or the
	// latest checkpoint was never anchored.
	AnchorToken    []byte
	AnchoredAt     *time.Time
	AnchorProvider string
	// AnchorTrustRootConfigured is true when a TSA trust root
	// (audit.checkpoint_notary.ca_cert_path) is configured, i.e. this server is
	// actually able to locally re-verify AnchorToken against a root of trust.
	// Only meaningful when AnchorToken is non-empty. When false, AnchorToken was
	// still merely RECORDED (a raw TSA receipt was obtained and stored) but this
	// server has never checked it against any root of trust — callers must not
	// treat a recorded-but-unverifiable anchor as equivalent to a verified one.
	AnchorTrustRootConfigured bool

	// Truncated is set only by VerifyAuditChainSegment: the MaxRows cap stopped
	// the walk before ThroughID or the end of the chain, so rows after HeadID
	// were NOT verified.
	Truncated bool

	// Seals is the number of accepted audit losses (internal/core/audit_seal.go,
	// `admin audit accept-loss`) the core's walk stepped over; SealReason
	// describes them. Valid with Seals > 0 means the rows that remain verify
	// and the chain is NOT whole: every report shows it as "sealed", never as
	// valid. Never set by the storage layer.
	Seals      int
	SealReason string
}

// AuditChainAnchor is an authenticated re-anchor point for VerifyAuditChain's
// walk, produced when a retention purge (DeleteAuditLogsBefore) removes rows
// from the chained (post-ADR-029) region: the new earliest surviving row's own
// id, prev_hash (which now points at a deleted predecessor), and entry_hash.
//
// The store layer that walks the chain has no signing key and trusts this
// value literally — authenticating it (HMAC-signing at write time under the
// checkpoint signing key, verifying the signature before ever constructing one
// to pass in) is entirely the caller's (core layer's) responsibility. Without
// that, any DB-writable actor could forge an anchor claiming an arbitrary gap
// is sanctioned, defeating the tamper-evidence the chain exists to provide.
type AuditChainAnchor struct {
	RowID     uint
	PrevHash  string
	EntryHash string
	// PurgedEvents counts CHAINED rows removed by sanctioned retention purges
	// (#3257); legacy unchained rows are never counted, because the
	// checkpoint/high-water counts they are compared with never included them.
	// On a candidate returned by DeleteAuditLogsBefore it is the chained rows
	// THAT delete removed. On an anchor the core layer loaded and authenticated
	// it is the cumulative total, covered by the anchor's HMAC, so a DB-level
	// actor cannot raise it to excuse a truncation. Checkpoint and high-water
	// checks compare chained + PurgedEvents against the certified count.
	PurgedEvents int64
}

// AuditVerifyJobLockKey is the WithSchedulerLock key that admits one background
// full audit-chain verification job across replicas ("KEYSAVJB"; distinct from
// server/main.go's schedLock* keys; uniqueness against every *LockKey constant
// is guarded by store.TestEveryAdvisoryLockKeyConstantIsUnique).
const AuditVerifyJobLockKey int64 = 0x4B455953_41564A42

// AuditChainSegment bounds one VerifyAuditChainSegment walk. AfterID/SeedHash
// come from an authenticated source (a signed checkpoint head, or the signed
// incremental-verification state); like AuditChainAnchor, the store layer
// trusts them literally.
type AuditChainSegment struct {
	// AfterID is the pinned seed row; 0 = start at the chain start.
	AfterID uint
	// SeedHash is the entry_hash AfterID was certified/verified with.
	SeedHash string
	// Anchor is the authenticated retention anchor, used only when AfterID == 0.
	Anchor *AuditChainAnchor
	// ThroughID is the last id to walk (inclusive); 0 = to the end.
	ThroughID uint
	// MaxRows caps the rows walked after the pinned row; 0 = no cap.
	MaxRows int
}

// AuditChainMigrationResult reports the outcome of MigrateAuditChainEncoding.
type AuditChainMigrationResult struct {
	// RowsMigrated is the number of chained rows whose entry_hash/prev_hash
	// were (or, under dry-run, would be) rewritten.
	RowsMigrated int64
	// UnchainedRowsSkipped is the legacy pre-ADR-029 prefix left untouched.
	UnchainedRowsSkipped int64
	// HeadID/HeadHash are the migrated chain's final row id and its newly
	// computed entry_hash (auditGenesisHash-derived if RowsMigrated is 0).
	HeadID   uint
	HeadHash string
	// AnchorRowID/AnchorNewEntryHash are set when the earliest migrated row's
	// id matches the anchor the caller seeded this call with (seedPrevHash
	// came from a real retention anchor, not genesis) — the caller must re-sign
	// and persist an updated anchor for AnchorRowID using AnchorNewEntryHash
	// (its PrevHash is unchanged; it represents an already-purged predecessor
	// that cannot be recomputed). Zero/empty when no anchor applies.
	AnchorRowID        uint
	AnchorNewEntryHash string
}

// UnusedSecretStat is one row of the unused-secrets report. LastRead is nil when
// the secret has never been read.
type UnusedSecretStat struct {
	SecretID      uint       `json:"secret_id"`
	SecretName    string     `json:"secret_name"`
	EnvironmentID uint       `json:"environment_id"`
	LastRead      *time.Time `json:"last_read"`
}

// SecretReadEntry is one row in the secret read aggregation report, representing
// the total reads by a single actor (user or machine identity) within a window.
type SecretReadEntry struct {
	// ActorID is the actor identifier: a user's numeric ID rendered as a string,
	// or a machine identity name (from actor_type="machine_identity" rows).
	ActorID string `json:"actor_id"`
	// ActorUsername is the resolved display name for the actor, empty when the
	// user row is absent (e.g. deleted users or machine identities).
	ActorUsername string    `json:"actor_username,omitempty"`
	ReadCount     int64     `json:"read_count"`
	LastReadAt    time.Time `json:"last_read_at"`
}

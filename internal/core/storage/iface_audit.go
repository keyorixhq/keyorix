package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AuditStore is the Storage slice for audit log, chain verification, checkpoints, pending audit events and access logs.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type AuditStore interface {
	// LastUserSecretActivity returns, per user, the most recent secret-access time
	// in the project (from the audit trail). Backs dormant-access detection in the
	// access review — a grant whose principal has no recent activity is stale
	// standing access to prune. Users with no recorded activity are absent from the
	// map.
	LastUserSecretActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error)
	// LastUserRoleManagementActivity returns, per user, the most recent time they
	// granted/revoked a role or group-role attributable to this project (the
	// roles.assign-tier half of admin-tier dormant-role-grant detection: #258,
	// narrowed per-permission by #487). A plain secrets.read/write role is
	// considered "used" by any entry in LastUserSecretActivity, but a role that
	// additionally confers role-management (e.g. project_admin's roles.assign)
	// should only be considered "used" via THIS capability if the principal
	// actually exercised it — routine secret reads (or even a SEPARATE admin-tier
	// grant's secrets.delete activity) under a different grant must not mask this
	// one as active. Users with no recorded role-management activity are absent
	// from the map.
	LastUserRoleManagementActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error)
	// LastUserSecretDeletionActivity returns, per user, the most recent time they
	// deleted a secret attributable to this project (the secrets.delete/admin-tier
	// half of admin-tier dormant-role-grant detection: #258, narrowed
	// per-permission by #487) — see LastUserRoleManagementActivity's doc for why
	// this is kept separate rather than folded into one combined "elevated
	// activity" signal. Users with no recorded deletion activity are absent from
	// the map.
	LastUserSecretDeletionActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error)
	// LastUserSecretReadActivity returns, per user, the most recent secret.read
	// time attributable to this project — the secrets.read half of plain-tier
	// dormant-role-grant detection (#487 round 112). Mirrors
	// LastUserRoleManagementActivity/LastUserSecretDeletionActivity's per-
	// permission split, one level down from admin-tier: before this, a plain-tier
	// grant was credited "used" by ANY secret activity (read OR write) in
	// LastUserSecretActivity regardless of which specific permission (secrets.read
	// vs secrets.write) the grant's OWN bundle actually confers, so a user holding
	// a read-only grant AND a separate write-only grant in the same project had
	// BOTH masked non-dormant by either one's activity. Users with no recorded
	// read activity are absent from the map.
	LastUserSecretReadActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error)
	// LastUserSecretWriteActivity returns, per user, the most recent
	// secret.created/updated/rotated time attributable to this project — the
	// secrets.write half of plain-tier dormant-role-grant detection (#487 round
	// 112). See LastUserSecretReadActivity's doc for why this is kept separate
	// rather than folded into one combined signal. Users with no recorded write
	// activity are absent from the map.
	LastUserSecretWriteActivity(ctx context.Context, projectID uint, since time.Time) (map[uint]time.Time, error)

	// Audit Logging
	LogAuditEvent(ctx context.Context, event *models.AuditEvent) error
	// LogAuditEventWithAccessLog is LogAuditEvent plus a secret_access_logs row,
	// committed together as one atomic unit (SESSION-PERF, #2403 follow-up, item 3)
	// — a caller that needs both (e.g. a secret read) gets them as one call
	// instead of two separate writes that could succeed/fail independently.
	// accessLog may be nil.
	LogAuditEventWithAccessLog(ctx context.Context, event *models.AuditEvent, accessLog *models.SecretAccessLog) error
	CreateSecretAccessLog(ctx context.Context, log *models.SecretAccessLog) error
	ListSecretAccessLogs(ctx context.Context, secretID uint, since time.Time) ([]models.SecretAccessLog, error)
	// CountSecretReadsBySecretIDs returns, for every secret in secretIDs with at
	// least one qualifying row, the number of "read" access-log entries at or
	// after since — aggregated in SQL (GROUP BY + COUNT), not one
	// ListSecretAccessLogs call per secret. Used by the rotation planner's
	// risk-scoring batch (#409); a secret absent from the result had zero
	// qualifying reads, same as ListSecretAccessLogs returning an empty slice.
	CountSecretReadsBySecretIDs(ctx context.Context, secretIDs []uint, since time.Time) (map[uint]int, error)
	// PrincipalSecretFirstSeen returns, for every non-empty accessed_by with at least
	// one access log row at or after `since`, the earliest access time per secret it
	// touched in that range — aggregated in SQL (GROUP BY + MIN), not loaded as full
	// log rows, so this stays cheap regardless of per-secret read volume. Backs the
	// anomaly detector's per-principal breadth-exfiltration pass (#101): a principal
	// reading many DIFFERENT secrets it has never touched before is invisible to the
	// per-secret rules (each secret only sees one unremarkable access), so this
	// aggregates across secrets by principal instead. See the LocalStorage
	// implementation's doc comment for why `since` must stay a coarse (date-scale)
	// bound rather than a narrow live-window one.
	PrincipalSecretFirstSeen(ctx context.Context, since time.Time) (map[string]map[uint]time.Time, error)
	// ListSecretIDsAccessedSince returns the distinct secret IDs with at least one
	// access-log row (any action, any accessor) at or after since. Backs the anomaly
	// detector's incremental sweep: a secret with no access-log row in the detection
	// horizon cannot trip any per-secret rule, so the detector skips its per-secret
	// access-log reads instead of sweeping every secret on every pass.
	ListSecretIDsAccessedSince(ctx context.Context, since time.Time) ([]uint, error)
	// MostAccessedSecrets returns the most-read secrets (optionally scoped to a
	// project and, further, to a single environment within it) in the window
	// since `since`, ordered by read count descending, capped at `limit`. Backs
	// the usage-analytics dashboard.
	MostAccessedSecrets(ctx context.Context, projectID, environmentID *uint, since time.Time, limit int) ([]SecretUsageStat, error)
	// UnusedSecrets returns secrets (optionally scoped to a project and, further,
	// to a single environment within it) with no read access since
	// `notReadSince` — including never-read secrets — ordered never-read first,
	// then oldest last read.
	UnusedSecrets(ctx context.Context, projectID, environmentID *uint, notReadSince time.Time) ([]UnusedSecretStat, error)
	// CountUnusedSecretsByProject returns, for every project in projectIDs in a
	// single grouped query, the count of secrets not read since notReadSince (or
	// never read) — the deployment-wide counterpart to UnusedSecrets, used by the
	// hygiene rollup (#393) instead of calling UnusedSecrets once per project. A
	// project absent from the result has zero unused secrets.
	CountUnusedSecretsByProject(ctx context.Context, projectIDs []uint, notReadSince time.Time) (map[uint]int, error)
	// GetSecretReadCounts aggregates "secret.read" audit events for the given
	// secret in the time window [since, until), returning the top-N actors sorted
	// by read count desc. Used by the secret read aggregation report.
	GetSecretReadCounts(ctx context.Context, secretID uint, since, until time.Time, limit int) ([]SecretReadEntry, error)
	GetAuditLogs(ctx context.Context, filter *AuditFilter) ([]*models.AuditEvent, int64, error)
	// MaxAuditEventID returns the highest audit_events.id (0 when the table is
	// empty): an O(1) read of the primary key's right edge. Scheduler jobs that
	// keep an id high-water mark read it first and bound their scan with
	// AuditFilter.UpToID, so a run costs O(rows added since the last run).
	MaxAuditEventID(ctx context.Context) (uint, error)
	// AuditRetentionStats returns the total audit event count and the oldest /
	// newest event timestamps. Keyorix never purges audit events, so these raw
	// aggregates let an operator demonstrate how far back the trail reaches
	// (NIS2 mandates 12 months of retention). Oldest/Newest are nil on an empty
	// table.
	AuditRetentionStats(ctx context.Context) (*AuditRetentionStats, error)
	// DeleteAuditLogsBefore hard-deletes the longest contiguous id prefix of
	// AuditEvent rows whose event_time is ALL before cutoff (INV-STORE-22,
	// #2633) — never a row past the first one that is not, so a row whose
	// event_time is out of id order is retained rather than cut out of the
	// middle of the hash chain — under the same KEYAUDIT lock appends use.
	// Returns the number of rows deleted, plus a re-anchor candidate when the
	// delete reached into the chained (post-ADR-029) region: the new earliest
	// surviving row's id/prev_hash/entry_hash, for the caller to authenticate
	// (HMAC, checkpoint signing key) and persist as the retention anchor BEFORE
	// VerifyAuditChain can walk the surviving chain again — nil when nothing
	// chained was deleted (nothing to re-anchor). The candidate's PurgedEvents
	// is the number of chained rows this delete removed. See AuditChainAnchor.
	DeleteAuditLogsBefore(ctx context.Context, cutoff time.Time) (int64, *AuditChainAnchor, error)
	// VerifyAuditChain re-walks the tamper-evidence hash chain (ADR-029) over
	// audit_events and reports whether it is intact. The first divergence —
	// modified field, deleted/inserted row, or broken linkage — is reported
	// with the offending event id. A leading run of pre-ADR-029 rows with empty
	// hashes is counted as an unchained legacy prefix, not a failure.
	//
	// anchor, when non-nil, seeds the walk at a legitimately-moved chain start
	// (a retention purge removed the original earliest rows) instead of
	// requiring the true genesis: the earliest surviving row must match
	// anchor.RowID/PrevHash/EntryHash exactly, or the chain is reported broken.
	// The caller MUST have already authenticated anchor (this layer trusts it
	// literally); pass nil to verify from genesis as before. A surviving chain
	// that already starts at genesis (the purge only removed the legacy
	// unchained prefix, or the table is now empty) ignores a non-nil anchor.
	VerifyAuditChain(ctx context.Context, anchor *AuditChainAnchor) (*AuditChainVerification, error)
	// VerifyAuditChainSegment walks one bounded part of the chain with the same
	// per-row rules as VerifyAuditChain (docs/specs/audit-incremental-verification.md).
	// With seg.AfterID == 0 it starts at the chain start exactly like
	// VerifyAuditChain(ctx, seg.Anchor). With seg.AfterID > 0 the row AfterID is
	// pinned first: it must exist, carry entry_hash == seg.SeedHash and recompute
	// from its own fields; the walk then continues with the rows id > AfterID,
	// the first of which must link to SeedHash. The walk stops after ThroughID
	// (0 = no bound) or MaxRows rows (0 = no bound). The result's HeadID/HeadHash
	// are the last row verified (the pinned row when nothing followed it), and
	// ChainedEvents counts the rows walked after the pinned row. Truncated
	// reports that MaxRows stopped the walk before ThroughID / the end.
	VerifyAuditChainSegment(ctx context.Context, seg AuditChainSegment) (*AuditChainVerification, error)
	// MigrateAuditChainEncoding re-derives entry_hash/prev_hash for every chained
	// audit_events row, in ascending id order, under computeAuditEntryHash's
	// current (length-prefixed) encoding — closing the gap left when that
	// encoding replaced the prior NUL-delimited one (a breaking, non-content-
	// preserving hash-format change; see computeAuditEntryHash's doc comment).
	// The unchained legacy prefix (pre-ADR-029 rows with an empty entry_hash) is
	// left untouched.
	//
	// anchor has EXACTLY the same meaning and applicability rule as
	// VerifyAuditChain's own anchor parameter: when non-nil AND the earliest
	// chained row's CURRENTLY STORED prev_hash is not auditGenesisHash (a prior
	// sanctioned retention purge moved the chain start), the walk seeds from
	// anchor.PrevHash instead of genesis. The caller MUST have already
	// authenticated anchor; this layer trusts it literally.
	//
	// Holds the same cross-process exclusivity LogAuditEvent uses (Postgres
	// advisory lock; SQLite's own single-writer semantics) for the ENTIRE
	// migration, in one transaction — not just per batch — so no concurrently
	// appended row can be hashed against a partially-migrated chain. Callers
	// MUST ensure no other process can reach this database's audit_events table
	// for the duration (this transaction only prevents concurrent writes
	// THROUGH this same storage backend's own LogAuditEvent path, not from an
	// entirely separate process/connection pool bypassing it).
	//
	// dryRun computes and returns the same result WITHOUT persisting anything
	// (the transaction is rolled back), so an operator can preview row/anchor
	// counts before committing.
	MigrateAuditChainEncoding(ctx context.Context, dryRun bool, anchor *AuditChainAnchor) (*AuditChainMigrationResult, error)
	// CreateAuditCheckpoint appends a signed checkpoint of the chain head (ADR-029).
	CreateAuditCheckpoint(ctx context.Context, cp *models.AuditCheckpoint) error
	// UpdateAuditCheckpointAnchor stores the external-notary anchor (RFC 3161 token,
	// asserted time, provider) on an existing checkpoint row (ADR-029); the signed
	// fields stay immutable.
	UpdateAuditCheckpointAnchor(ctx context.Context, id uint, token []byte, anchoredAt time.Time, provider string) error
	// LatestAuditCheckpoint returns the most recently written checkpoint, or
	// (nil, nil) when none exists yet.
	LatestAuditCheckpoint(ctx context.Context) (*models.AuditCheckpoint, error)
	// AuditEntryHashByID returns the entry_hash of the audit row with the given
	// id; found is false when no such row exists (e.g. it was truncated away).
	AuditEntryHashByID(ctx context.Context, id uint) (hash string, found bool, err error)

	// Pending audit events (models.PendingAuditEvent): audit rows owed by an
	// operation that took effect without waiting for the audit log (a plain secret
	// suspend). Created in the operation's own transaction; ClaimPendingAuditEvent
	// (a delete reporting whether this call removed the row) runs in the same
	// transaction as the owed row's append, so each owed row is written once.
	CreatePendingAuditEvent(ctx context.Context, p *models.PendingAuditEvent) error
	ListPendingAuditEvents(ctx context.Context, afterID uint, limit int) ([]*models.PendingAuditEvent, error)
	ClaimPendingAuditEvent(ctx context.Context, id uint) (claimed bool, err error)
	RecordPendingAuditEventFailure(ctx context.Context, id uint, reason string) error
	CountPendingAuditEvents(ctx context.Context) (int64, error)
	// OldestPendingAuditEventAt is the created_at of the oldest owed audit event; found
	// is false when none is pending. A plain read on the created_at index (no lock, no
	// scan), cheap enough to run on every metrics scrape.
	OldestPendingAuditEventAt(ctx context.Context) (at time.Time, found bool, err error)
	GetDistinctActiveUserIDs(ctx context.Context, since time.Time) ([]uint, error)
	// CountImpersonatedActions returns the number of impersonated audit events
	// recorded for actingAs by impersonator since `since`, excluding the
	// impersonation.start/impersonation.end markers themselves. Used to report
	// the action count on an impersonation.end event.
	CountImpersonatedActions(ctx context.Context, actingAs, impersonator uint, since time.Time) (int64, error)
}

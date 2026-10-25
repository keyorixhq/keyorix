package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// SecretStore is the Storage slice for secrets, versions, dependencies, schedules and version comments.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type SecretStore interface {
	// Secret dependency edges (ADR-052) — the per-project secret dependency graph.
	CreateSecretDependency(ctx context.Context, d *models.SecretDependency) (*models.SecretDependency, error)
	GetSecretDependency(ctx context.Context, id uint) (*models.SecretDependency, error)
	ListSecretDependenciesForProject(ctx context.Context, projectID uint) ([]*models.SecretDependency, error)
	DeleteSecretDependency(ctx context.Context, id uint) error
	// ListSecretDependenciesForProjectForUpdate is ListSecretDependenciesForProject,
	// taking a row-level write lock on every returned edge on backends that support
	// one (Postgres FOR UPDATE), mirroring LockUserForUpdate/
	// ListGlobalAdminAssignmentsForUpdate (#260). Retained as a raw storage
	// primitive but no longer used by AddSecretDependency
	// (internal/core/secret_dependencies.go) — see CreateSecretDependencyExclusive
	// below for why the cycle-check read and the edge write had to be collapsed
	// into ONE storage-layer call rather than orchestrated by the caller across
	// this method and CreateSecretDependency.
	ListSecretDependenciesForProjectForUpdate(ctx context.Context, projectID uint) ([]*models.SecretDependency, error)
	// CreateSecretDependencyExclusive atomically validates and persists one secret
	// dependency edge under a project-scoped exclusive lock (Postgres FOR UPDATE),
	// rejecting it with storage.ErrDuplicateSecretDependency or
	// storage.ErrSecretDependencyCycle if the CURRENT edge set (read under that
	// same lock) already contains the pair, or adding it would close a cycle.
	//
	// This is what AddSecretDependency now calls instead of orchestrating
	// ListSecretDependenciesForProjectForUpdate + CreateSecretDependency itself
	// inside a WithTransaction (#260's original design): the now-deleted
	// RemoteStorage's WithTransaction was a no-op passthrough — no real transaction
	// spanned the wire — so a caller-driven "list under lock, decide, then create"
	// sequence against a RemoteStorage backend was really two independent HTTP
	// round trips with no lock held between them, silently losing #260's whole
	// guarantee for any downstream server booted with storage.type: remote
	// (ADR-049) — including the exact case that guarantee exists for: multiple
	// such downstream replicas racing to add a reciprocal edge pair against the
	// SAME upstream project concurrently. Collapsing the check-and-write into one
	// storage-interface call fixed that: LocalStorage's implementation runs the
	// identical duplicate/cycle logic AddSecretDependency used to run itself, just
	// moved down a layer and wrapped in one real DB transaction — the same
	// wire-code-translation technique that preserves CreateProjectMembership's
	// DB-level unique-index atomicity across a remote boundary (#511), just for an
	// invariant (acyclicity) no unique index can express.
	CreateSecretDependencyExclusive(ctx context.Context, d *models.SecretDependency) (*models.SecretDependency, error)

	// Temporal access schedule — restricts a secret's reads to a configured
	// time window (day-of-week + hour range). GetSecretAccessSchedule returns
	// nil, nil when no schedule has been configured for the secret.
	GetSecretAccessSchedule(ctx context.Context, secretNodeID uint) (*models.SecretAccessSchedule, error)
	SetSecretAccessSchedule(ctx context.Context, schedule *models.SecretAccessSchedule) error
	DeleteSecretAccessSchedule(ctx context.Context, secretNodeID uint) error
	// GetSecretScheduleAndLatestVersion is GetSecretAccessSchedule plus
	// GetLatestSecretVersion for one secret, for a latest-version value read
	// (PERF-FIX-4, collapse C5): the schedule row and the latest-version cache
	// generation come from ONE statement (one snapshot), and the version row is
	// read only when the version cache misses. The returned error is the shared
	// statement's failure only; a latest-version failure is carried in
	// LatestVersionErr, exactly as GetLatestSecretVersion would have returned it,
	// so the caller still judges the schedule first.
	GetSecretScheduleAndLatestVersion(ctx context.Context, secretNodeID uint) (*SecretScheduleAndLatestVersion, error)

	// Secret Management
	//
	// CreateSecret persists secret's metadata; secret itself carries no value
	// field at all (models.SecretNode has none — the plaintext normally lives
	// only in core.CreateSecretRequest.Value and is routed to a separate
	// CreateSecretVersion call core.CreateSecret makes right after this one).
	// The optional plaintextValue variadic (#499) existed ONLY for the now-deleted
	// RemoteStorage: its upstream HTTP handler required "value" in the SAME POST
	// /api/v1/secrets body and created version 1 atomically as part of handling
	// it, with no separate "create metadata now, add the value later" route to
	// call instead. LocalStorage's implementation has always ignored this
	// parameter — the value flows through the existing, unchanged
	// CreateSecretVersion path — but callers (internal/core/secrets.go) still
	// construct and pass it on every call, for a backend that no longer exists.
	// Candidate for a follow-up cleanup: drop the parameter, ValueStored
	// (models.SecretNode), and the now-always-false branch in core.CreateSecret
	// that checks it — left untouched here since it threads through the
	// interface, LocalStorage, and the generated fault-injection wrapper, and
	// deserves its own reviewed PR rather than riding along with a comment sweep.
	CreateSecret(ctx context.Context, secret *models.SecretNode, plaintextValue ...string) (*models.SecretNode, error)
	GetSecret(ctx context.Context, id uint) (*models.SecretNode, error)
	// GetSecretsByIDs is the batch form of GetSecret: every secret in ids, in one
	// query, instead of one GetSecret call per ID. IDs with no matching row are
	// simply absent from the result (no error) — same as GetSecret's own
	// not-found case, just without the per-ID error wrapping. Used by the rotation
	// planner's risk-scoring batch (#409) so scoring N candidate secrets costs a
	// small constant number of queries, not N.
	GetSecretsByIDs(ctx context.Context, ids []uint) ([]*models.SecretNode, error)
	// Batch name lookups for list views (LIST-ENDPOINTS-1): one query per page
	// instead of one GetUser / GetGroup / GetMachineIdentity / GetSecretTags per
	// row. Each selects only the id and display column. An id with no live row is
	// absent from the map (no error), as the single-row getters report not-found.
	// GetSecretTagsBySecretIDs returns name-ordered tags; an untagged secret is absent.
	GetUsernamesByIDs(ctx context.Context, ids []uint) (map[uint]string, error)
	// GetUserBriefsByIDs is GetUsernamesByIDs plus the email (id, username, email columns only).
	GetUserBriefsByIDs(ctx context.Context, ids []uint) (map[uint]UserBrief, error)
	GetGroupNamesByIDs(ctx context.Context, ids []uint) (map[uint]string, error)
	GetMachineIdentityNamesByIDs(ctx context.Context, ids []uint) (map[uint]string, error)
	GetSecretTagsBySecretIDs(ctx context.Context, ids []uint) (map[uint][]string, error)
	GetSecretByName(ctx context.Context, name string, projectID, environmentID uint) (*models.SecretNode, error)
	// UpdateSecretFields persists ONLY the fields f names, onto a LIVE secret
	// row: "UPDATE secret_nodes SET <named columns> WHERE id = ? AND deleted_at
	// IS NULL". matched=false (no error) means the secret is gone; the caller
	// must not report success. See SecretFieldUpdate.
	//
	// This REPLACES the former UpdateSecret, a bare GORM Save of a struct the
	// caller read earlier and unlocked (#2695). Being on the SHARED primitive,
	// every one of its eight callers inherited two defects at once:
	//
	//   - Save's 0-rows fallback upserts with deleted_at = NULL, so ANY of them
	//     landing after a concurrent DeleteSecret RESURRECTED the secret — and
	//     DeleteSecret also revokes its shares and ACLs, so the secret came
	//     back without them, with no secret.restored audit event and without
	//     going through RestoreSecret;
	//   - Save writes every column, so each caller reverted whatever a narrower
	//     concurrent writer had changed since its own read: SuspendSecret's
	//     status=suspended (an incident freeze), TryIncrementSecretNodeReadCount's
	//     read_count (re-opening a spent MaxReads budget),
	//     ClearProjectSecretOwnership's owner_id=0 (an offboarded user regains
	//     the owner short-circuit), and the rotation columns.
	//
	// Per-field pointers are the fix, not a convenience: each caller names only
	// the columns it owns, so no caller can revert another's. A caller that
	// populates everything is visible as exactly that in a diff.
	UpdateSecretFields(ctx context.Context, id uint, f SecretFieldUpdate) (matched bool, err error)
	// UpdateSecret is the full-row Save UpdateSecretFields replaces. It is kept
	// ONLY because one caller still needs it: SetSecretAutoRotate
	// (rotation_executor.go), which is #2650's site and is converted to a
	// column-scoped UpdateSecretRotationConfig by open PR #2668 — in the same
	// few lines of this file. Deleting it here would make #2695 conflict with a
	// PR the coordinator is about to merge, for no safety gain, since that one
	// call site is exactly what #2668 fixes.
	//
	// Do not add a caller. TestUpdateSecret_HasNoProductionCallerBeyond2668
	// fails if one appears, and fails again once #2668 lands and the last one
	// goes away — at which point this method and that test both get deleted.
	UpdateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error)
	// TransitionSecretStatus persists secret's full row via a single conditional
	// write — "UPDATE ... WHERE id = ? AND status = ?" — succeeding only if the
	// row's CURRENT persisted status still equals fromStatus (the value the
	// caller observed via GetSecret immediately before mutating secret.Status in
	// memory), mirroring UpdateProjectInvitation's `WHERE id = ? AND state =
	// 'pending'` pattern and TransitionMachineIdentityState's `WHERE id = ? AND
	// state = ?` pattern exactly, just for SecretNode.Status. Returns whether the
	// write actually matched a row.
	//
	// This exists because SuspendSecret/ResumeSecret (internal/core/
	// secret_suspend.go) previously did a plain read-then-unconditional-
	// UpdateSecret: a suspend racing a resume on the same secret could silently
	// clobber each other depending on write order with no error to either
	// caller, and — because UpdateSecret persists the FULL in-memory struct —
	// any OTHER field mutated by a concurrent, unrelated operation between the
	// read and this write would be silently reverted to the stale value read at
	// the top, a general lost-update problem. And because the now-deleted
	// RemoteStorage's WithTransaction was a no-op passthrough, a naive two-call
	// GetSecret-then-UpdateSecret sequence run against it got NONE of the
	// atomicity a real DB transaction + conditional write provides, reopening the
	// same race across the HTTP hop. Routing the write through this one
	// conditional round trip instead
	// restores the same guarantee LocalStorage already has: a false match
	// result must be treated exactly like a lost race — surfaced as an error to
	// the caller — not retried or silently overwritten.
	TransitionSecretStatus(ctx context.Context, secret *models.SecretNode, fromStatus string) (bool, error)
	// UpdateSecretRotationConfig persists ONLY secret's auto-rotation columns
	// (auto_rotate, rotation_length, rotation_charset, rotation_backend,
	// rotation_ref) plus updated_at, via one conditional "UPDATE ... WHERE id = ?
	// AND project_id = ? AND rotation_backend = ? AND deleted_at IS NULL". It
	// succeeds only if the secret is still live, still in the project the caller
	// authorized against, and its CURRENT rotation_backend still equals
	// fromBackend — the pre-read value core.SetSecretAutoRotate's admin gate
	// (#90) was decided on. Returns whether the write matched a row; a false
	// result is a lost race and must fail closed, never be retried blind.
	//
	// It exists because SetSecretAutoRotate used to persist its pre-read
	// snapshot with UpdateSecret's full-row Save, which undeleted a concurrently
	// deleted secret (Save's upsert fallback writes deleted_at = NULL), reverted
	// a concurrent admin's backend binding and restored cleared ownership (#2650).
	UpdateSecretRotationConfig(ctx context.Context, secret *models.SecretNode, fromBackend string) (bool, error)
	DeleteSecret(ctx context.Context, id uint) error
	// RestoreSecret clears a soft-deleted secret's deleted_at (ADR-033).
	RestoreSecret(ctx context.Context, id uint) error
	// GetSecretIncludingDeleted loads a secret even if soft-deleted (Unscoped),
	// so the restore route can resolve a deleted secret's scope (ADR-033).
	GetSecretIncludingDeleted(ctx context.Context, id uint) (*models.SecretNode, error)
	ListSecrets(ctx context.Context, filter *SecretFilter) ([]*models.SecretNode, int64, error)
	// ListOrphanedSecrets returns a project's live secrets whose owner is no longer
	// a live user (the owner was deleted/soft-deleted) — offboarding hygiene, so an
	// admin can re-assign ownership. Scoped to the project via the environment JOIN.
	ListOrphanedSecrets(ctx context.Context, projectID uint) ([]*models.SecretNode, error)
	// CountOrphanedSecretsByProject returns the orphaned-secret count (same
	// definition as ListOrphanedSecrets) for every project in projectIDs, in a
	// single grouped query keyed by project ID — the deployment-wide counterpart
	// used by the hygiene rollup (#393) instead of calling ListOrphanedSecrets once
	// per project. A project absent from the result has zero orphaned secrets.
	CountOrphanedSecretsByProject(ctx context.Context, projectIDs []uint) (map[uint]int, error)
	// CountExpiringSecretsByProject returns, for every project in projectIDs in a
	// single grouped query, the count of live secrets with a non-null expiration
	// before expiresBefore — the deployment-wide counterpart to the
	// ListSecrets(ExpiresBefore) count ProjectHygieneSummary uses per-project
	// (#393). A project absent from the result has zero expiring secrets.
	CountExpiringSecretsByProject(ctx context.Context, projectIDs []uint, expiresBefore time.Time) (map[uint]int, error)
	// CountSecretsByEnvironment returns, for every environment in envIDs in a
	// single grouped query, the number of live secrets (folders and soft-deleted
	// rows excluded) — the server-side source of the environment list's
	// secret_count (DASH-SIGNALS-1). An environment absent from the result has
	// zero secrets.
	CountSecretsByEnvironment(ctx context.Context, envIDs []uint) (map[uint]int64, error)
	// ListLiveSecretNamesByProject returns every live secret (folders excluded)
	// across every project in projectIDs — id/name/type/classification/environment
	// plus its project ID — in a SINGLE query ordered by project then name, capped at
	// limit total rows. This is the deployment-wide counterpart to the per-project
	// ListSecrets call SecretNameConformance uses (#416): naming-policy regex
	// matching is not a SQL concern, so this intentionally returns raw rows for the
	// caller to check against the policy in memory — only the N+1 QUERY pattern
	// (one ListSecrets call per project) is eliminated, not the in-memory regex
	// work. The returned bool reports whether limit was hit (result truncated).
	ListLiveSecretNamesByProject(ctx context.Context, projectIDs []uint, limit int) ([]SecretNameRow, bool, error)
	// GetSecretTags returns a secret's tag names (sorted). SetSecretTags replaces a
	// secret's tags wholesale, upserting Tag rows by name — secret organization/search.
	GetSecretTags(ctx context.Context, secretID uint) ([]string, error)
	SetSecretTags(ctx context.Context, secretID uint, tagNames []string) error
	// ListProjectSecretsForDrift returns one lightweight row per secret in the
	// project (folders excluded, secrets in soft-deleted environments excluded),
	// carrying just the fields cross-environment drift detection pivots on:
	// environment id, name, type, and whether expiration / max_reads are set. No
	// secret values are read.
	ListProjectSecretsForDrift(ctx context.Context, projectID uint) ([]DriftSecretRow, error)
	GetSecretVersions(ctx context.Context, secretID uint) ([]*models.SecretVersion, error)
	CreateSecretVersion(ctx context.Context, version *models.SecretVersion) (*models.SecretVersion, error)
	GetLatestSecretVersion(ctx context.Context, secretID uint) (*models.SecretVersion, error)
	// SetSecretCertNotAfter caches a certificate-typed secret's parsed leaf expiry
	// (ADR-056), a targeted column update with no other side effects.
	SetSecretCertNotAfter(ctx context.Context, secretID uint, notAfter *time.Time) error
	// SetRetentionOverride sets the RetentionOverrideDays on a SecretNode row.
	// days = 0 clears the override (reverts to the global policy).
	SetRetentionOverride(ctx context.Context, secretID uint, days int) error
	IncrementSecretReadCount(ctx context.Context, versionID uint) error
	// TryIncrementSecretReadCount atomically increments a version's read count only
	// while it is still below maxReads, in a single conditional UPDATE. Returns true
	// when the increment happened (the read is within the cap), false when the cap is
	// already reached (or the version is gone). This is the race-free gate for
	// max-reads enforcement: concurrent reads can never collectively exceed the cap.
	TryIncrementSecretReadCount(ctx context.Context, versionID uint, maxReads int) (bool, error)
	// TryIncrementSecretNodeReadCount is TryIncrementSecretReadCount's secret-level
	// twin (#133): keyed on the SECRET, not a version, so the count carries forward
	// across rotate/rollback creating a new version — a per-version counter resets
	// to zero on every new version, letting a burn-after-N-reads secret become
	// re-readable simply by rolling back. This is the authoritative max-reads gate;
	// TryIncrementSecretReadCount remains for the per-version read_count DISPLAY
	// field only.
	TryIncrementSecretNodeReadCount(ctx context.Context, secretID uint, maxReads int) (bool, error)
	// ListSecretsWithQuota returns every live secret (IsSecret=true, not
	// soft-deleted) whose MaxReads pointer is set and greater than zero —
	// the full candidate set for the read-quota alert job. No values are read.
	ListSecretsWithQuota(ctx context.Context) ([]models.SecretNode, error)

	// Secret version comments — free-text annotations on a specific secret version,
	// providing a human-readable audit trail of why a version was created or changed.
	// List/Delete are scoped by secretID/versionID (not just the comment's own primary
	// key) so a caller authorized on one secret cannot reach another's comments (#G53).
	CreateSecretVersionComment(ctx context.Context, c *models.SecretVersionComment) error
	ListSecretVersionComments(ctx context.Context, secretID, versionID uint) ([]models.SecretVersionComment, error)
	DeleteSecretVersionComment(ctx context.Context, secretID, versionID, id uint) error
}

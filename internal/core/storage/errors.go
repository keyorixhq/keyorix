package storage

import (
	"errors"

	"github.com/keyorixhq/keyorix/internal/storage/remote"
)

// ErrUserNotFound is returned (wrapped) by GetUser when the user positively does not
// exist, as distinct from a transient retrieval failure. Callers that must fail
// closed on uncertainty — e.g. authorization decisions keyed on "is this account
// gone?" — should match it with errors.Is rather than treating any error as absence.
var ErrUserNotFound = errors.New("user not found")

// ErrRoleNotAssigned is returned (wrapped) by RemoveRole when the (user, role, scope)
// row positively does not exist — e.g. it already auto-expired or was already
// removed — as distinct from a genuine storage failure. Callers for whom "already
// gone" is an acceptable outcome (idempotent removal) should match it with
// errors.Is rather than swallowing every error identically.
var ErrRoleNotAssigned = errors.New("role not assigned")

// ErrWouldStrandLastAdmin is returned (wrapped) by RemoveGlobalAdminRoleGuarded when
// removing the (user, role) grant at the global scope would leave the install with
// zero super_admin/admin/system_admin holders (#340, #525) — the storage-layer
// sentinel for guardLastGlobalAdmin's refusal, preserved across the RemoteStorage HTTP
// hop the same way ErrDuplicateSecretDependency/ErrSecretDependencyCycle are.
var ErrWouldStrandLastAdmin = errors.New("refusing to remove the last install administrator")

// ErrBreakGlassNotActive is returned (wrapped) when a conditional break-glass state
// transition (e.g. revoke) finds the activation is no longer in the expected prior
// state — most often because a concurrent revoke already won the race. Distinct
// from a genuine storage failure; callers should surface it as "already revoked"
// rather than a generic error.
var ErrBreakGlassNotActive = errors.New("break-glass activation is not active")

// ErrDuplicateActiveMembership is returned (wrapped) by CreateProjectMembership when the
// insert collides with the partial unique index on (project_id, user_id) scoped to
// non-revoked rows. InviteMember's own "no active membership" check races with a
// concurrent invite for the same pair (#309 TOCTOU); this lets the loser of that race
// be told cleanly that the membership already exists, rather than surfacing a raw
// constraint-violation error or silently leaving an orphaned row.
var ErrDuplicateActiveMembership = errors.New("an active membership already exists for this project and user")

// ErrDuplicateEmail is returned (wrapped) by CreateUser/CreateUserWithRoleGrants/UpdateUser
// when the write collides with the partial, case-insensitive unique index on users.email
// (live rows only). Every email-uniqueness check in this codebase (CreateUser, signup,
// invite-accept, SSO JIT-provision, SCIM provision/update) is a check-then-act read
// followed by a later write, which is inherently racy — two concurrent calls for the
// identical email can both pass their pre-check before either commits (#117). The DB-level
// index makes the loser's write fail here instead of silently minting a second account
// sharing the email (which left GetUserByEmail resolving to an arbitrary one of them);
// callers translate this into a clean "email already in use" error rather than a raw
// constraint-violation message.
var ErrDuplicateEmail = errors.New("a user with this email already exists")

// ErrDuplicateProjectName is returned (wrapped) by CreateProject/UpdateProject when the
// write collides with the partial, case-insensitive unique index on projects.name (live
// rows only, #385). Without this, "Production"/"production" landed as two distinct,
// both-succeeding rows — and the CLI's project name resolution (resolveProjectID)
// resolves case-insensitively over an unordered project list, returning the FIRST match —
// so a same-name-different-case shadow project could silently hijack a later `keyorix
// secret import/export --project production`. Callers translate this into a clean
// "project name already in use" error rather than a raw constraint-violation message.
var ErrDuplicateProjectName = errors.New("a project with this name already exists")

// ErrDuplicateSecretVersion is returned (wrapped) by CreateSecretVersion when the insert
// collides with the unique index on (secret_node_id, version_number). RotateSecret's
// GetLatestSecretVersion -> +1 -> storeSecretVersion sequence is a read-then-write race
// (#121): two concurrent rotations of the same secret can both read the same "latest"
// version and both attempt to write the same next version_number. The unique index makes
// the loser's write fail here instead of silently producing two rows sharing one
// version_number; callers retry with a freshly re-read latest version rather than failing
// the rotation outright on ordinary concurrent contention.
var ErrDuplicateSecretVersion = errors.New("a secret version with this version number already exists")

// ErrUnsupportedByBackend is returned (wrapped) by a storage.Storage implementation
// when an operation has no meaningful implementation under the ACTIVE backend —
// distinct from a transient failure of that backend. The original motivating case
// (#452) was RemoteStorage's login-attempt methods (a server proxying
// storage.type: remote had no server-side counter to proxy the call to); that gap is
// now closed — RemoteStorage.RecordLoginAttempt/CountRecentLoginAttempts/
// PruneLoginAttempts genuinely proxy to a real upstream endpoint (see
// internal/storage/store/remote_login_attempts.go and
// server/http/handlers/login_attempts_proxy.go) — but the sentinel remains in active
// use for the structurally identical gap #454 found on account-state/login-lockout
// mutation (RemoteStorage.UpdateLoginLockoutState — those fields have no wire
// representation in the generic user-update endpoint at all, unlike the
// login-attempt counter which had a natural dedicated endpoint to add). Callers that
// treat "storage error" as "fail open" (rate_limit.go, login_lockout.go) should
// errors.Is against this to distinguish a permanent architectural gap — worth a
// loud, one-time operator warning — from an ordinary transient DB/network error that
// doesn't warrant one.
var ErrUnsupportedByBackend = errors.New("operation not supported by the active storage backend")

// ErrBreakGlassAlreadyActive is returned (wrapped) by CreateBreakGlassActivation when
// the partial unique index on (project_id, user_id) WHERE state='active' rejects the
// insert: a concurrent activation for the same project+user already won the race and
// is active. This closes the check-then-act gap between ActivateBreakGlass's
// "no existing active activation" list-and-scan check and its own insert — under a
// race, both callers could pass the check before either inserted; the DB constraint
// is the actual source of truth. Callers should match it with errors.Is to surface
// the same friendly "already active" message a losing racer gets from the earlier
// application-level check.
var ErrBreakGlassAlreadyActive = errors.New("an active break-glass grant already exists for this project and user")

// ErrDuplicateDynamicSecretConfig is returned (wrapped) by CreateDynamicSecretConfig
// when the insert collides with the unique index on dynamic_secret_configs
// (project_id, environment_id, name, #462), matching DynamicSecretConfig's own doc
// comment ("one per (project, env, name)") — previously documented but not enforced.
// Callers translate this into a clean validation error instead of a raw
// constraint-violation message.
var ErrDuplicateDynamicSecretConfig = errors.New("a dynamic-secret config with this name already exists in this project and environment")

// ErrDuplicateReminderNotification is returned (wrapped) by CreateNotification when
// the insert collides with the partial unique index on notifications (user_id, type,
// project_id) scoped to unread rotation/expiry reminders (#488). Both
// SendRotationReminders and SendExpiryReminders dedupe with a check-then-act read
// (GetUnreadNotification) followed by a separate CreateNotification call, which is a
// TOCTOU race: unlike the scheduled path (single-replica-gated via WithSchedulerLock,
// ADR-039), the on-demand admin-jobs HTTP trigger
// (POST /api/v1/admin/jobs/rotation-reminders or .../expiry-reminders) has no lock at
// all, so two concurrent runs (or one racing the scheduler's own tick) against a
// project with no existing reminder can both pass the "does a reminder already exist"
// check before either commits, producing duplicate reminder rows. The index makes the
// loser's insert fail here instead of silently duplicating; callers treat this as a
// benign no-op skip, not a failure.
var ErrDuplicateReminderNotification = errors.New("an unread reminder notification already exists for this user, type, and project")

// ErrDuplicateSecretDependency is returned (wrapped) by CreateSecretDependencyExclusive
// when the CURRENT edge set (read under this call's own lock — see that method's doc)
// already contains the same (dependent, depends_on) pair. Backed by the real unique
// index on secret_dependencies (idx_secret_dep_edge), so a plain CreateSecretDependency
// insert would also fail with a unique-constraint violation for the exact same case;
// CreateSecretDependencyExclusive additionally checks it up front (alongside the cycle
// check, which the index cannot express) so both rejections share one code path and one
// sentinel. Callers translate this into a clean "already exists" validation error.
var ErrDuplicateSecretDependency = errors.New("this secret dependency already exists")

// ErrSecretDependencyCycle is returned (wrapped) by CreateSecretDependencyExclusive when
// adding the edge would make the depends_on secret transitively depend on the dependent
// secret, closing a cycle in the project's dependency graph (ADR-052). Unlike
// ErrDuplicateSecretDependency, no DB constraint can express "acyclic" directly, so this
// is evaluated in application code against the lock-consistent edge read
// CreateSecretDependencyExclusive takes — see its doc for why that check must run in the
// SAME storage-layer call as the write (#260), not as a separate caller-orchestrated
// read-then-write, once a real cross-call transaction can no longer be assumed
// (RemoteStorage.WithTransaction is a no-op passthrough). Callers translate this into a
// clean "would create a cycle" validation error.
var ErrSecretDependencyCycle = errors.New("this secret dependency would create a cycle")

// IsUserNotFound reports whether err represents "this user positively does not
// exist" under EITHER active storage backend (#504). LocalStorage wraps the
// ErrUserNotFound sentinel above (errors.Is); RemoteStorage instead returns a
// remote.HTTPError for every 4xx/5xx response, with its own IsNotFound()
// helper keyed on the actual HTTP status (errors.As). Neither of those is
// reliably detectable by matching an error's rendered text — the i18n string
// LocalStorage happens to embed in ErrUserNotFound's wrapping message is an
// implementation detail, not a contract, and a RemoteStorage error never
// contained it in the first place (round 112's #501 fix gave RemoteStorage a
// structured error but multiple internal/core call sites still matched the
// old i18n text and so never worked against storage.type: remote, before or
// after that fix). Callers that must distinguish "genuinely absent" from a
// transient retrieval failure across both backends should use this instead of
// either check alone.
func IsUserNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrUserNotFound) {
		return true
	}
	var httpErr *remote.HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.IsNotFound()
	}
	return false
}

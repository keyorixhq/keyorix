package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// UserStore is the Storage slice for user accounts, lifecycle state, lockout and password history.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type UserStore interface {
	// User Management
	//
	// CreateUser persists user, which by this point already carries its final
	// bcrypt PasswordHash (`json:"-"` — core.buildUserForCreate hashes and
	// discards the caller-supplied plaintext before ever reaching here). The
	// optional plaintextPassword variadic (#499) existed ONLY for the now-deleted
	// RemoteStorage: its upstream HTTP handler re-hashed its own bcrypt copy
	// server-side and therefore required the PLAINTEXT password in its request
	// body, not a hash it could not verify was produced honestly. LocalStorage's
	// implementation has always ignored this parameter (it already has the hash
	// and never additionally receives, logs, or persists the plaintext) — same
	// follow-up cleanup candidate as CreateSecret's plaintextValue above (drop the
	// parameter; call sites still construct and pass it for a backend that no
	// longer exists).
	CreateUser(ctx context.Context, user *models.User, plaintextPassword ...string) (*models.User, error)
	// CreateUserWithRoleGrants creates the user and applies all role grants in a
	// single transaction (ADR-028 atomic provisioning); on any failure nothing is
	// persisted.
	CreateUserWithRoleGrants(ctx context.Context, user *models.User, grants []RoleGrant) (*models.User, error)
	GetUser(ctx context.Context, id uint) (*models.User, error)
	// LockUserForUpdate re-reads a user by ID inside a WithTransaction, taking a
	// row-level write lock on backends that support one (Postgres: SELECT … FOR
	// UPDATE) so a read-modify-write on the row serializes against concurrent writers
	// across replicas. On backends without row locks (SQLite) it is a plain read, and
	// the caller is responsible for its own process-level serialization. Returns the
	// typed ErrUserNotFound when the user is absent. Use this — not GetUser — whenever
	// a transaction increments or conditionally mutates per-user counters (e.g. the
	// login-lockout failed-attempt count) that must not lose updates under concurrency.
	LockUserForUpdate(ctx context.Context, id uint) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	// UpdateUserIfActiveStateMatches persists ONLY the profile columns core.UpdateUser
	// applies in memory from a request (username/username_folded, email/
	// email_folded, display name, the new IsActive value, updated_at) — never the
	// full row, so it cannot revert a concurrent narrow write to any other column
	// (SetAccountState, SetPasswordHash, MFA, lockout; #2653/#2654) — via a single
	// conditional "UPDATE ... WHERE id = ? AND is_active = ?", succeeding only if
	// the row's CURRENT persisted is_active still equals fromActive (the value
	// core.UpdateUser observed via GetUser, i.e. wasActive, before applying any of the
	// request's field changes in memory). Returns whether the write actually
	// matched a row, mirroring TransitionMachineIdentityState's `WHERE id = ? AND
	// state = ?` / UpdateProjectInvitation's `WHERE id = ? AND state = 'pending'`
	// pattern (#388/#412) for this codebase's other state-transition TOCTOU class.
	//
	// core.UpdateUser is a general-purpose multi-field update (username, email,
	// display name, IsActive, ...) and persists every request through THIS
	// method: IsActive can flip concurrently with any other update touching the
	// same user (a profile edit racing an admin deactivation, or two
	// deactivation attempts racing each other), and a plain write would
	// silently clobber whichever change lost the race, with no error to either
	// caller. (STORE-DEAD-PRIMITIVES-1 deleted the full-row UpdateUser storage
	// primitive that used to sit beside this one: it had no caller and its
	// Save could revert any column.) This exists for the exact same reason
	// TransitionMachineIdentityState does: the now-deleted RemoteStorage's
	// WithTransaction was a no-op passthrough, so a naive GetUser-then-write
	// sequence run against it got none of the atomicity LocalStorage provides
	// via a real DB transaction — routing the actual write through this one
	// conditional round trip restores the same guarantee LocalStorage already
	// has, without making any validation decision here: the caller
	// (core.UpdateUser) still decides which fields to mutate and what
	// fromActive to assert before calling this; a false match result must be
	// treated as a lost-race error, not retried or silently overwritten.
	UpdateUserIfActiveStateMatches(ctx context.Context, user *models.User, fromActive bool) (bool, error)
	// UpdateLastLogin stamps the user's last_login_at column without touching any
	// other field (no updated_at bump). Called on every successful login.
	UpdateLastLogin(ctx context.Context, userID uint, loginAt time.Time) error
	// SetAccountState persists ONLY the account_state column (plus updated_at) —
	// a column-scoped write, deliberately not a full-row save (#454), which could
	// revert any concurrent writer's column: an admin
	// suspend/reactivate (setAccountState) or a SCIM deprovision/reactivate (UpdateSCIMUser,
	// via the conditional SetAccountStateIfMatches below) is an explicit, security-relevant directive, not passive accounting — the caller must
	// see a hard error rather than a false "success" that leaves the account state
	// unchanged if this write ever fails.
	SetAccountState(ctx context.Context, id uint, state string, updatedAt time.Time) error
	// SetAccountStateIfMatches is SetAccountState made conditional on the row's
	// CURRENT account_state still being fromState (the value the caller read
	// before computing toState): "UPDATE ... SET account_state, updated_at WHERE
	// id = ? AND account_state = ? AND deleted_at IS NULL". matched=false (no
	// error) means the row moved — or is gone — since that read; the caller must
	// fail closed rather than revert a concurrent writer's state (e.g. a SCIM
	// reactivation must not turn a suspension that committed after its read back
	// into active). Used by the SCIM lifecycle paths, whose new state is derived
	// from the old one (applySCIMActiveState, DeprovisionSCIMUser); see
	// C-RACE-FIX-B2. A NULL column is matched by fromState "".
	SetAccountStateIfMatches(ctx context.Context, id uint, fromState, toState string, updatedAt time.Time) (bool, error)
	// ClaimUserExternalIDIfUnset persists ONLY external_id (plus updated_at) for
	// a user whose external_id is still UNSET and whose row is still live:
	// "UPDATE ... SET external_id, updated_at WHERE id = ? AND
	// COALESCE(external_id,'') = '' AND deleted_at IS NULL". claimed=false (no
	// error) means someone else federated the account first, or it is gone.
	//
	// This is resolveSSOUser's first-federation write (#2699). It used a
	// full-row save (the since-deleted full-row storage user writer), whose GORM Save upsert-fallback resurrected
	// an account an admin had deleted after resolveSSOUser's unlocked read —
	// writing back deleted_at=NULL, is_active=true, account_state=active — and
	// the same window also reverted a concurrent suspension, password change,
	// MFA enable or lockout. Narrow and conditional here; the caller re-reads
	// afterwards so its login gate sees the committed row, not its own stale
	// snapshot.
	ClaimUserExternalIDIfUnset(ctx context.Context, id uint, externalID string, updatedAt time.Time) (claimed bool, err error)
	// SetPasswordHash persists ONLY the password_hash and password_changed_at columns
	// (plus updated_at) — a column-scoped write, deliberately not a full-row save,
	// which could revert a concurrent lockout, MFA or account-state write (#484, the
	// same rationale as SetAccountState above). A password change
	// (applyNewPassword, shared by self-service ChangePassword and the setup-token
	// consume flow) is exactly the kind of explicit security directive #454 already
	// treats as needing fail-closed semantics for account_state: a user must never be
	// told their password changed when it silently didn't. Any accompanying
	// account_state clear (a restricted state resetting to active) is persisted
	// separately via SetAccountState, not folded into this primitive.
	//
	// It also CLEARS one_time_password_expires_at: any newly set password supersedes
	// a one-time password, so the expiry must never outlive the credential it
	// belonged to (OTP-EXPIRY-1). A caller that installs a one-time password calls
	// SetOneTimePasswordExpiry AFTER this, in the same transaction.
	SetPasswordHash(ctx context.Context, id uint, hash string, changedAt time.Time) error
	// SetOneTimePasswordExpiry persists ONLY one_time_password_expires_at (plus
	// updated_at): the instant after which the current one-time password is refused
	// at login (OTP-EXPIRY-1). nil clears it. Must run in the same transaction as
	// the SetPasswordHash that installs the one-time password.
	SetOneTimePasswordExpiry(ctx context.Context, id uint, expiresAt *time.Time, updatedAt time.Time) error
	// UpdateLoginLockoutState persists ONLY the four login-lockout accounting columns
	// (failed_login_attempts, last_failed_login_at, login_locked_until,
	// login_lockout_count) — the same #454 rationale as SetAccountState above. Unlike
	// SetAccountState, though, lockout accounting is a passive backstop counter, not an
	// explicit security directive (mirrors #452's identical call on
	// CountRecentLoginAttempts/RecordLoginAttempt): a genuine write failure here is a
	// best-effort, fail-open backstop degradation (see login_lockout.go), not a hard
	// error to the caller.
	UpdateLoginLockoutState(ctx context.Context, id uint, attempts int, lastFailedAt, lockedUntil *time.Time, lockoutCount int) error
	DeleteUser(ctx context.Context, id uint) error
	RestoreUser(ctx context.Context, id uint) error
	ListUsers(ctx context.Context, filter *UserFilter) ([]*models.User, int64, error)
	// ListUsersInStateBefore returns users whose account_state equals state and
	// who were created before the cutoff (ADR-025 stale-account warnings).
	ListUsersInStateBefore(ctx context.Context, state string, before time.Time) ([]*models.User, error)
	// ListInactiveUsers returns all live (non-deleted) users who have not logged
	// in since threshold: specifically, those whose last_login_at IS NULL AND
	// created_at < threshold, OR whose last_login_at < threshold. Used by the
	// inactivity auto-suspension job (SuspendInactiveUsers).
	ListInactiveUsers(ctx context.Context, threshold time.Time) ([]*models.User, error)
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	// GetUserByExternalID resolves a SCIM-provisioned user by the IdP's externalId
	// (RFC 7644). Returns the not-found error when no user carries that external id.
	GetUserByExternalID(ctx context.Context, externalID string) (*models.User, error)

	// Password history (ADR-025 history_count). AddPasswordHistory records a
	// bcrypt hash; RecentPasswordHashes returns the most recent `limit` hashes
	// (newest first); PrunePasswordHistory keeps only the newest `keep` rows.
	AddPasswordHistory(ctx context.Context, userID uint, hash string, at time.Time) error
	RecentPasswordHashes(ctx context.Context, userID uint, limit int) ([]string, error)
	PrunePasswordHistory(ctx context.Context, userID uint, keep int) error
}

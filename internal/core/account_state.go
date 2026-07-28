// account_state.go — user account lifecycle state machine (ADR-025).
//
// States:
//
//	active                    — normal; full access.
//	pending_first_login       — provisioned by an admin; must set a password
//	                            before doing anything else (restricted session).
//	password_reset_required   — admin forced a reset; restricted until changed.
//	suspended                 — login is refused entirely (admin security action).
//	deprovisioned             — login is refused; set by SCIM/IdP deactivation. Kept
//	                            distinct from `suspended` so an IdP reactivation clears
//	                            only its own deactivation and can never undo an admin's
//	                            security suspension (incident response wins).
//
// A "restricted" session (pending_first_login / password_reset_required)
// authenticates but the auth middleware blocks every endpoint except the
// password-change / profile allowlist, returning 403 so the client redirects to
// change-password. Completing a password change clears the restriction back to
// active. Admin transitions are audited.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Account states.
const (
	AccountActive                = "active"
	AccountPendingFirstLogin     = "pending_first_login"
	AccountPasswordResetRequired = "password_reset_required"
	AccountSuspended             = "suspended"
	// AccountDeprovisioned is set by SCIM/IdP deactivation. It blocks login exactly
	// like AccountSuspended, but is a separate value so SCIM reactivation can clear it
	// without clearing an admin's (stronger, sticky) AccountSuspended. See UpdateSCIMUser.
	AccountDeprovisioned = "deprovisioned"
)

// NormalizeAccountState maps the empty legacy value to active.
func NormalizeAccountState(state string) string {
	if state == "" {
		return AccountActive
	}
	return state
}

// validAccountStates is the canonical ADR-025 set a caller may explicitly write.
// The empty string is separately accepted by IsValidAccountState — it is legacy
// shorthand for "unset", normalized to active by NormalizeAccountState — but is
// deliberately not in this map so callers that want the exact persisted set can
// use it directly.
var validAccountStates = map[string]bool{
	AccountActive:                true,
	AccountPendingFirstLogin:     true,
	AccountPasswordResetRequired: true,
	AccountSuspended:             true,
	AccountDeprovisioned:         true,
}

// IsValidAccountState reports whether state is the empty string (legacy "unset",
// normalized to active) or one of the ADR-025 canonical lifecycle values. Any other
// string (a typo, wrong casing, or arbitrary garbage) is not a value any code path
// in this codebase ever writes itself. #334 originally used this to validate gRPC
// CreateUser's account_state field before persisting it; #135 replaced that with
// ignoring the field entirely (mirroring the HTTP CreateUser handler, which never
// exposed it), so this validator no longer has a caller-controlled write path — kept
// for any future internal caller that needs to check a state before writing it.
func IsValidAccountState(state string) bool {
	return state == "" || validAccountStates[state]
}

// AccountRestricted reports whether a state forces a password change before the
// user may use any non-allowlisted endpoint.
//
// Fail-CLOSED default: an unrecognized state (default case below) is treated as
// restricted, not as active/unrestricted. This is the defense-in-depth backstop
// for #334 — IsValidAccountState now rejects a bad value at the one caller-
// controlled write path, but this function must still cope with an unrecognized
// value already sitting in the database (e.g. written before this fix shipped, or
// by a future path that forgets to validate). Restricting is a safe default here
// specifically because it is *not* a lockout: a restricted session still
// authenticates (see AccountLoginBlocked) and self-heals the moment the user next
// changes their password (clearRestrictionOnPasswordChange resets a restricted
// state to active), so the failure mode of a garbage value is "forced through the
// password-change flow", never "silently full access" and never "permanently
// locked out with no recovery path".
func AccountRestricted(state string) bool {
	switch NormalizeAccountState(state) {
	case AccountActive, AccountSuspended, AccountDeprovisioned:
		// Suspended/deprovisioned are already refused outright by
		// AccountLoginBlocked, so "restricted" is moot for them either way.
		return false
	case AccountPendingFirstLogin, AccountPasswordResetRequired:
		return true
	default:
		return true
	}
}

// AccountLoginBlocked reports whether a state refuses login outright. Both an admin
// suspension and a SCIM/IdP deactivation block login; every login/session/token path
// funnels through here, so a deprovisioned account is refused everywhere a suspended
// one is, with no per-path change.
//
// Unlike AccountRestricted, this deliberately keeps a fail-OPEN default (false, not
// blocked) for an unrecognized state. Blocking login outright has no self-healing
// path — a fully blocked user can never reach the password-change flow to fix
// anything — so failing closed here would risk permanently locking out an already-
// legitimate user over a merely malformed value (e.g. a stale data migration, or a
// value from a since-removed state) with no recovery short of direct DB/admin
// intervention. AccountRestricted's fail-closed default already guarantees an
// unrecognized value can never grant full unrestricted access; that is the correct
// place for the defense-in-depth backstop, not here.
func AccountLoginBlocked(state string) bool {
	switch NormalizeAccountState(state) {
	case AccountSuspended, AccountDeprovisioned:
		return true
	default:
		return false
	}
}

// StaleAccounts returns users that have sat in the given account_state longer
// than olderThan — by default pending_first_login accounts an admin provisioned
// but the user never completed (ADR-025 stale-account warnings; surfaced at >7
// days). Oldest first.
func (c *KeyorixCore) StaleAccounts(ctx context.Context, state string, olderThan time.Duration) ([]*models.User, error) {
	if state == "" {
		state = AccountPendingFirstLogin
	}
	before := c.now().Add(-olderThan)
	return c.storage.ListUsersInStateBefore(ctx, state, before)
}

// SuspendUser blocks a user's login. Admin action; audited. The bootstrap/admin
// caller is responsible for not suspending themselves into a lockout.
func (c *KeyorixCore) SuspendUser(ctx context.Context, adminID, userID uint) error {
	return c.setAccountState(ctx, adminID, userID, AccountSuspended, "account.suspended")
}

// ReactivateUser returns a suspended (or otherwise non-active) user to active.
func (c *KeyorixCore) ReactivateUser(ctx context.Context, adminID, userID uint) error {
	return c.setAccountState(ctx, adminID, userID, AccountActive, "account.reactivated")
}

// RequirePasswordReset forces the user into a restricted session until they
// change their password. Admin action; audited.
func (c *KeyorixCore) RequirePasswordReset(ctx context.Context, adminID, userID uint) error {
	return c.setAccountState(ctx, adminID, userID, AccountPasswordResetRequired, "account.password_reset_required")
}

// setAccountState persists a new account state and writes an audit event.
//
// #344: this read-modify-write races with UpdateSCIMUser's — a routine SCIM/IdP
// resync's GetUser can read the row before an admin's SuspendUser here commits, and
// whichever caller's full-row Save lands last would otherwise win outright, silently
// reverting the other's change with no error to either side. accountStateMu (held for
// the whole read-modify-write, not just the DB write) serializes this against
// UpdateSCIMUser in-process, and LockUserForUpdate's row lock (Postgres: SELECT ...
// FOR UPDATE) does the same across replicas — the identical pattern recordFailedLogin
// uses for the login-lockout counter (see login_lockout.go).
//
// #454: persists via SetAccountState, not the generic UpdateUser — an admin
// suspend/reactivate is an explicit security directive, so a backend that cannot
// actually persist account_state (RemoteStorage, storage.type: remote) must fail this
// call outright rather than silently succeed while the account stays unchanged. See
// SetAccountState's doc comment on storage.Storage.
func (c *KeyorixCore) setAccountState(ctx context.Context, adminID, userID uint, state, eventType string) error {
	if userID == 0 {
		return fmt.Errorf("user ID is required")
	}
	c.accountStateMu.Lock()
	defer c.accountStateMu.Unlock()

	var sessionHashes []string
	err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		// The lock-guarded read is still needed for serialization (row lock + existence
		// check) even though its returned user struct is no longer written back wholesale.
		if _, err := tx.LockUserForUpdate(ctx, userID); err != nil {
			return err
		}
		// Capture the user's current session-token HASHES BEFORE mutating so we can evict
		// their auth-cache entries after commit. The HTTP auth cache fast path serves a
		// frozen identity without re-reading the DB, so without eviction a
		// suspend/deactivate/restrict would not take effect until the positive-cache TTL —
		// a window where a blocked user keeps full access. The stored session_token IS the
		// SHA-256 hash, which is exactly the cache key.
		sessionHashes, _ = tx.ListSessionTokenHashesForUser(ctx, userID)
		// Also collect PAT hashes for cache eviction for ANY state transition, including
		// restricted states like password_reset_required. Without this, a cached PAT
		// bypasses the restriction for up to validTokenTTL (30 s) — ValidatePATToken
		// sees the old identity from the cache and never re-checks the new account state
		// (#r125-H2). We evict here without revoking; revoking follows for blocked states.
		if pats, _ := tx.ListPersonalAccessTokensByUser(ctx, userID); len(pats) > 0 {
			sessionHashes = append(sessionHashes, activePATHashes(pats)...)
		}

		if err := tx.SetAccountState(ctx, userID, state, c.now()); err != nil {
			return err
		}
		// A state that blocks login must also terminate the user's existing sessions AND
		// PATs, so suspension is effective immediately instead of lingering until the
		// token expires. ValidateSessionToken/ValidatePATToken also reject blocked
		// accounts as a slow-path backstop, but the cache fast path bypasses it — so
		// evict here too. Revoked PAT hashes are folded into sessionHashes so they're
		// evicted from the auth cache alongside the session hashes after commit.
		if AccountLoginBlocked(state) {
			_ = tx.DeleteSessionsForUserExcept(ctx, userID, 0)
			if hashes, herr := tx.RevokeAllPersonalAccessTokensForUser(ctx, userID); herr == nil {
				sessionHashes = append(sessionHashes, hashes...)
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to update account state: %w", err)
	}
	// Evict the captured session/PAT-token hashes from the auth cache — AFTER commit,
	// so a rolled-back transaction never evicts a still-valid cache entry — so the new
	// state (blocked, or merely restricted) is reflected on the very next request, not
	// after the cache TTL.
	c.invalidateTokenCache(sessionHashes...)
	aid := adminID
	c.writeAuditEventFull(ctx, eventType, &aid, nil, nil, "",
		fmt.Sprintf("user %d account state set to %s", userID, state))
	return nil
}

// activePATHashes returns the token hashes of all non-revoked PATs that have a hash,
// used to evict them from the auth cache after an account-state transition.
func activePATHashes(pats []*models.PersonalAccessToken) []string {
	var hashes []string
	for _, p := range pats {
		if !p.Revoked && p.TokenHash != "" {
			hashes = append(hashes, p.TokenHash)
		}
	}
	return hashes
}

// clearRestrictionOnPasswordChange returns the account state a user should hold
// after a successful password change: a restricted state clears to active; any
// other state is left unchanged.
func clearRestrictionOnPasswordChange(state string) string {
	if AccountRestricted(state) {
		return AccountActive
	}
	return NormalizeAccountState(state)
}

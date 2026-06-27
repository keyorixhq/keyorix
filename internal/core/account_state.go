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

// AccountRestricted reports whether a state forces a password change before the
// user may use any non-allowlisted endpoint.
func AccountRestricted(state string) bool {
	switch NormalizeAccountState(state) {
	case AccountPendingFirstLogin, AccountPasswordResetRequired:
		return true
	default:
		return false
	}
}

// AccountLoginBlocked reports whether a state refuses login outright. Both an admin
// suspension and a SCIM/IdP deactivation block login; every login/session/token path
// funnels through here, so a deprovisioned account is refused everywhere a suspended
// one is, with no per-path change.
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
func (c *KeyorixCore) setAccountState(ctx context.Context, adminID, userID uint, state, eventType string) error {
	if userID == 0 {
		return fmt.Errorf("user ID is required")
	}
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	// Capture the user's current session-token HASHES BEFORE mutating so we can evict their
	// auth-cache entries. The HTTP auth cache fast path serves a frozen identity without
	// re-reading the DB, so without eviction a suspend/deactivate/restrict would not take
	// effect until the positive-cache TTL — a window where a blocked user keeps full access.
	// The stored session_token IS the SHA-256 hash, which is exactly the cache key.
	sessionHashes, _ := c.storage.ListSessionTokenHashesForUser(ctx, userID)

	user.AccountState = state
	user.UpdatedAt = c.now()
	if _, err := c.storage.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to update account state: %w", err)
	}
	// A state that blocks login must also terminate the user's existing sessions AND PATs,
	// so suspension is effective immediately instead of lingering until the token expires.
	// ValidateSessionToken/ValidatePATToken also reject blocked accounts as a slow-path
	// backstop, but the cache fast path bypasses it — so evict here too.
	if AccountLoginBlocked(state) {
		_ = c.storage.DeleteSessionsForUserExcept(ctx, userID, 0)
		if hashes, herr := c.storage.RevokeAllPersonalAccessTokensForUser(ctx, userID); herr == nil {
			c.invalidateTokenCache(hashes...)
		}
	}
	// Evict the captured session-token hashes from the auth cache so the new state (blocked,
	// or merely restricted) is reflected on the very next request, not after the cache TTL.
	c.invalidateTokenCache(sessionHashes...)
	aid := adminID
	c.writeAuditEventFull(ctx, eventType, &aid, nil, nil, "",
		fmt.Sprintf("user %d account state set to %s", userID, state))
	return nil
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

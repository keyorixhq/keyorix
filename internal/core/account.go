// account.go — Self-service account operations for the authenticated user.
//
// These power the "My Account" page (ADR-021) and are deliberately scoped to the
// caller's own user ID: the HTTP layer never forwards a target user ID, role, or
// active flag from the request body. For admin user management see users.go.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"golang.org/x/crypto/bcrypt"
)

// UpdateOwnProfile updates the caller's display name and email only. It delegates
// to UpdateUser (which enforces email uniqueness) but constructs the request from
// the authenticated userID, so a caller can never change username/is_active or
// target another user.
//
// An email change additionally requires the caller's current password, mirroring
// ChangePassword's re-authentication check. The email is often the recovery/identity
// anchor (password reset delivery, SSO account linking — see ADR-052/ADR-053 related
// fixes) so a hijacked session (stolen cookie/token, unattended device) must not be
// able to silently repoint it to an attacker-controlled address and ride the
// password-reset flow to full takeover. Display-name-only changes are unaffected and
// need no password. currentPassword is ignored when the email is not changing.
func (c *KeyorixCore) UpdateOwnProfile(ctx context.Context, userID uint, displayName, email, currentPassword string) (*models.User, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	if email != "" {
		user, err := c.storage.GetUser(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
		}
		if email != user.Email {
			// For MFA-enabled accounts, require a TOTP code or password via requireReauth
			// (the same bar as DisableMFA / DeleteWebAuthnCredential). The email is the
			// password-reset anchor and SSO linking key: redirecting it to an
			// attacker-controlled address with only a stolen session suffices for full
			// account takeover. Password-only re-auth is too weak when a second factor is
			// enrolled. For non-MFA accounts, fall back to the bcrypt password check.
			if user.MFAEnabled {
				if err := c.requireReauth(ctx, user, currentPassword, "email_change"); err != nil {
					return nil, err
				}
			} else if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword)); err != nil {
				return nil, fmt.Errorf("%w: current password is incorrect", ErrIncorrectCurrentPassword)
			}
		}
	}
	return c.UpdateUser(ctx, &UpdateUserRequest{
		ID:          userID,
		DisplayName: displayName,
		Email:       email,
	})
}

// ChangePassword verifies the caller's current password and sets a new one. On
// success it drops the caller's other sessions (keeping the one identified by
// keepSessionToken) so a credential change invalidates other devices. If the
// current session cannot be resolved from keepSessionToken (e.g. a PAT-authenticated
// request), all of the user's sessions are dropped.
func (c *KeyorixCore) ChangePassword(ctx context.Context, userID uint, current, newPassword, keepSessionToken string) error {
	if userID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}

	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(current)); err != nil {
		return fmt.Errorf("%w: current password is incorrect", ErrIncorrectCurrentPassword)
	}
	// Enforce policy + history after the current-password check so an attacker can't
	// probe the policy without already holding valid credentials (ADR-025).
	if err := c.validateNewPassword(ctx, user, newPassword); err != nil {
		return err
	}
	if err := c.applyNewPassword(ctx, user, newPassword); err != nil {
		return err
	}

	// Drop OTHER sessions and evict them from the auth cache, so a thief holding a
	// stolen session is locked out immediately on the next request — not after the
	// cache TTL. Best-effort: the password change itself has succeeded.
	var keepID uint
	var keepHash string
	if keepSessionToken != "" {
		if s, serr := c.storage.GetSession(ctx, keepSessionToken); serr == nil {
			keepID = s.ID
			keepHash = s.SessionToken
		}
	}
	_ = c.deleteSessionsForUserAndEvict(ctx, userID, keepID, keepHash)
	return nil
}

// SetTokenCacheInvalidator wires the HTTP auth-cache eviction function (by token hash)
// so core token-revocation paths can evict immediately. Called once at startup.
func (c *KeyorixCore) SetTokenCacheInvalidator(fn func(hash string)) {
	c.tokenCacheInvalidator = fn
}

// invalidateTokenCache evicts the given token hashes from the auth cache when an
// invalidator is wired (a no-op otherwise — e.g. tests, where the cache doesn't exist).
func (c *KeyorixCore) invalidateTokenCache(hashes ...string) {
	if c.tokenCacheInvalidator == nil {
		return
	}
	for _, h := range hashes {
		if h != "" {
			c.tokenCacheInvalidator(h)
		}
	}
}

// evictUserSessionCache evicts every one of the user's active sessions from the HTTP
// auth cache WITHOUT deleting the sessions themselves — unlike
// deleteSessionsForUserAndEvict, the user stays logged in. Used after a permission
// change (e.g. role removal) where the goal is only to force the NEXT request to
// re-resolve the user's permissions from storage instead of serving a stale,
// positively-cached authorization decision for up to validTokenTTL.
func (c *KeyorixCore) evictUserSessionCache(ctx context.Context, userID uint) {
	hashes, _ := c.storage.ListSessionTokenHashesForUser(ctx, userID)
	c.invalidateTokenCache(hashes...)
}

// deleteSessionsForUserAndEvict deletes all of the user's sessions except keepID and
// evicts the deleted sessions from the HTTP auth cache, so a revoked session stops
// authenticating on the very NEXT request rather than lingering for the positive-cache
// TTL. The stored session_token IS the SHA-256 cache key. keepHash (the kept session's
// stored hash, or "") is never evicted, so the caller's own session is not disturbed.
// Best-effort: the session deletion is the durable control; eviction is the immediacy.
func (c *KeyorixCore) deleteSessionsForUserAndEvict(ctx context.Context, userID, keepID uint, keepHash string) error {
	hashes, _ := c.storage.ListSessionTokenHashesForUser(ctx, userID)
	err := c.storage.DeleteSessionsForUserExcept(ctx, userID, keepID)
	for _, h := range hashes {
		if h != "" && h != keepHash {
			c.invalidateTokenCache(h)
		}
	}
	return err
}

// validateNewPassword checks a candidate password against the configured policy and
// the password-history rule, without mutating anything. Split from applyNewPassword
// so callers (e.g. the setup-token consume flow) can reject a weak password BEFORE
// spending a single-use token, rather than burning the link on a policy failure.
func (c *KeyorixCore) validateNewPassword(ctx context.Context, user *models.User, newPassword string) error {
	if err := c.passwordPolicy.Validate(newPassword, user); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	// Stateful history rule: forbid reuse of the last N passwords (ADR-025).
	if c.passwordReused(ctx, user, newPassword) {
		return fmt.Errorf("%s: password must not reuse a recent password", i18n.T("ErrorValidation", nil))
	}
	return nil
}

// applyNewPassword hashes newPassword, stamps it on the user (clearing a restricted
// account state back to active per ADR-025), persists the user, and records the hash
// in history. It assumes the password has already passed validateNewPassword. Shared
// by ChangePassword and the setup-token consume flow so password handling is uniform.
//
// #484: persists via the narrow SetPasswordHash (and, only when the account state
// actually needs to clear a restriction, SetAccountState) rather than the generic
// UpdateUser — RemoteStorage can never express password_hash in its wire format at
// all (models.User.PasswordHash is json:"-"), so a caller going through the generic
// read-modify-write succeeds against LocalStorage but silently no-ops under
// storage.type: remote, leaving the caller told "success" while the password never
// actually changed. Both writes run inside one transaction so a partial application
// (hash persisted but the state clear lost, or vice versa) can't happen on backends
// that support real transactions.
func (c *KeyorixCore) applyNewPassword(ctx context.Context, user *models.User, newPassword string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), int(bcryptCost.Load()))
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	now := c.now()
	newState := clearRestrictionOnPasswordChange(user.AccountState)
	// Compare against the NORMALIZED current state, not the raw field: an unset legacy
	// AccountState ("") normalizes to AccountActive, exactly like newState does for a
	// non-restricted user, so a naive raw comparison would spuriously call
	// SetAccountState (and, on RemoteStorage, hard-fail) for every legacy-row password
	// change even though nothing is actually changing.
	stateChanged := newState != NormalizeAccountState(user.AccountState)

	err = c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		if err := tx.SetPasswordHash(ctx, user.ID, string(hash), now); err != nil {
			return err
		}
		if stateChanged {
			if err := tx.SetAccountState(ctx, user.ID, newState, now); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	user.PasswordHash = string(hash)
	user.PasswordChangedAt = &now
	user.AccountState = newState
	user.UpdatedAt = now

	// Record the new hash in history and prune to the configured depth.
	// Best-effort: the password change itself has already succeeded.
	if c.passwordPolicy.HistoryCount > 0 {
		_ = c.storage.AddPasswordHistory(ctx, user.ID, string(hash), now)
		_ = c.storage.PrunePasswordHistory(ctx, user.ID, c.passwordPolicy.HistoryCount)
	}

	// Revoke the user's PATs too. A credential change must invalidate EVERY bearer class,
	// not just sessions — otherwise a thief who minted a (possibly non-expiring) PAT from a
	// stolen session survives the victim's reset. Best-effort; evict each from the auth
	// cache immediately so a revoked PAT can't keep authenticating for the cache TTL.
	if hashes, herr := c.storage.RevokeAllPersonalAccessTokensForUser(ctx, user.ID); herr == nil {
		c.invalidateTokenCache(hashes...)
	}
	return nil
}

// passwordReused reports whether newPassword matches the user's current password
// or any of the most recent HistoryCount stored hashes (ADR-025 history_count).
// Returns false when the history rule is disabled.
func (c *KeyorixCore) passwordReused(ctx context.Context, user *models.User, newPassword string) bool {
	if c.passwordPolicy.HistoryCount <= 0 {
		return false
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(newPassword)) == nil {
		return true
	}
	hashes, err := c.storage.RecentPasswordHashes(ctx, user.ID, c.passwordPolicy.HistoryCount)
	if err != nil {
		return false // best-effort: a history lookup failure must not block a change
	}
	for _, h := range hashes {
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(newPassword)) == nil {
			return true
		}
	}
	return false
}

// PasswordExpired reports whether the user's password has exceeded the policy's
// max age (ADR-025 max_age_days). Returns false when expiry is disabled. For
// legacy rows with no PasswordChangedAt, the account creation time is used.
func (c *KeyorixCore) PasswordExpired(user *models.User) bool {
	if user == nil || c.passwordPolicy.MaxAgeDays <= 0 {
		return false
	}
	set := user.PasswordChangedAt
	if set == nil {
		if user.CreatedAt.IsZero() {
			return false
		}
		set = &user.CreatedAt
	}
	maxAge := time.Duration(c.passwordPolicy.MaxAgeDays) * 24 * time.Hour
	return c.now().Sub(*set) > maxAge
}

// enforcePasswordExpiryGate transitions an active user to password_reset_required
// when the configured max_age_days policy has elapsed (ADR-025). Called at
// session-mint time so every subsequent API request is hard-gated by
// EnforceAccountRestriction, not just the client-side soft flag in the login
// response.
//
// Only transitions active → password_reset_required; other states (already
// restricted, suspended, deprovisioned) are left unchanged. Fails closed: a
// storage error is returned so an expired password cannot bypass the gate due
// to a transient write failure.
func (c *KeyorixCore) enforcePasswordExpiryGate(ctx context.Context, user *models.User) error {
	if !c.PasswordExpired(user) {
		return nil
	}
	if NormalizeAccountState(user.AccountState) != AccountActive {
		return nil
	}
	now := c.now()
	if err := c.storage.SetAccountState(ctx, user.ID, AccountPasswordResetRequired, now); err != nil {
		return fmt.Errorf("failed to enforce password expiry: %w", err)
	}
	user.AccountState = AccountPasswordResetRequired
	user.UpdatedAt = now
	return nil
}

// CurrentSessionID returns the session ID backing a session token, or 0 if the
// token is not a session (e.g. a PAT) or no longer exists. Used to flag the
// "current" row in the active-sessions list.
func (c *KeyorixCore) CurrentSessionID(ctx context.Context, token string) uint {
	if token == "" {
		return 0
	}
	s, err := c.storage.GetSession(ctx, token)
	if err != nil {
		return 0
	}
	return s.ID
}

// ListOwnSessions returns the caller's active sessions.
func (c *KeyorixCore) ListOwnSessions(ctx context.Context, userID uint) ([]*models.Session, error) {
	if userID == 0 {
		return nil, fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user ID is required")
	}
	return c.storage.ListSessionsByUser(ctx, userID)
}

// RevokeOwnSession deletes one of the caller's sessions after verifying ownership.
// A session that exists but belongs to another user is reported as not found, so a
// caller cannot probe for or revoke other users' session IDs.
func (c *KeyorixCore) RevokeOwnSession(ctx context.Context, userID, sessionID uint) error {
	if userID == 0 || sessionID == 0 {
		return fmt.Errorf("%s: %s", i18n.T("ErrorValidation", nil), "user and session IDs are required")
	}
	session, err := c.storage.GetSessionByID(ctx, sessionID)
	if err != nil || session.UserID != userID {
		return fmt.Errorf("%s: session not found", i18n.T("ErrorNotFound", nil))
	}
	if err := c.storage.DeleteSession(ctx, sessionID); err != nil {
		return err
	}
	// Evict the revoked session from the auth cache so the device is logged out on its
	// next request, not after the positive-cache TTL. session_token is the cache key.
	c.invalidateTokenCache(session.SessionToken)
	return nil
}

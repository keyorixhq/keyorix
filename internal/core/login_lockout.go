// login_lockout.go — per-account login lockout (brute-force protection). After
// MaxAttempts failed password logins within Window, the account is locked for an
// exponentially-backing-off cooldown; a successful login or an admin unlock resets
// it. This is distinct from the per-IP rate limiter (ADR-040): lockout binds to a
// specific account, so an attacker cannot evade it by rotating source IPs, and it
// rejects even a correct password while the lock is active. State lives on the User
// (failed_login_attempts / last_failed_login_at / login_locked_until /
// login_lockout_count); the lock auto-expires on read — no sweeper needed.
package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// LoginLockoutPolicy is the resolved lockout configuration (built from
// config.LoginLockoutConfig at startup). The zero value is disabled.
type LoginLockoutPolicy struct {
	Enabled      bool
	MaxAttempts  int
	Window       time.Duration
	BaseCooldown time.Duration
	MaxCooldown  time.Duration
}

const (
	EventAccountLocked   = "account.locked"
	EventAccountUnlocked = "account.unlocked"
)

// loginLocked reports whether the user is currently within an active lockout window.
func (c *KeyorixCore) loginLocked(user *models.User) bool {
	return c.loginLockout.Enabled && user.LoginLockedUntil != nil && c.now().Before(*user.LoginLockedUntil)
}

// cooldownFor returns the lock duration for the nth lockout (1-based): an
// exponential backoff BaseCooldown * 2^(n-1), capped at MaxCooldown.
func (p LoginLockoutPolicy) cooldownFor(lockoutCount int) time.Duration {
	cd := p.BaseCooldown
	for i := 1; i < lockoutCount && cd < p.MaxCooldown; i++ {
		cd *= 2
	}
	if cd > p.MaxCooldown {
		cd = p.MaxCooldown
	}
	return cd
}

// recordFailedLogin increments the user's failed-attempt counter (resetting it when
// the previous failure is older than the window) and locks the account once it
// reaches MaxAttempts. Best-effort persistence: a storage error must not change the
// "invalid credentials" outcome the caller returns.
func (c *KeyorixCore) recordFailedLogin(ctx context.Context, user *models.User) {
	if !c.loginLockout.Enabled {
		return
	}
	now := c.now()
	// A stale failure (older than the window) starts a fresh count.
	if user.LastFailedLoginAt != nil && now.Sub(*user.LastFailedLoginAt) > c.loginLockout.Window {
		user.FailedLoginAttempts = 0
	}
	user.FailedLoginAttempts++
	user.LastFailedLoginAt = &now

	if user.FailedLoginAttempts >= c.loginLockout.MaxAttempts {
		user.LoginLockoutCount++
		until := now.Add(c.loginLockout.cooldownFor(user.LoginLockoutCount))
		user.LoginLockedUntil = &until
		user.FailedLoginAttempts = 0 // window counter resets; the lock now gates
		uid := user.ID
		c.writeAuditEventFull(ctx, EventAccountLocked, &uid, nil, nil, "",
			fmt.Sprintf("account %d locked until %s after repeated failed logins (lockout #%d)",
				user.ID, until.UTC().Format(time.RFC3339), user.LoginLockoutCount))
	}
	_, _ = c.storage.UpdateUser(ctx, user)
}

// clearLoginFailures resets the lockout state after a successful authentication.
// It writes only when there is something to clear, so the happy path adds no extra
// write on every login.
func (c *KeyorixCore) clearLoginFailures(ctx context.Context, user *models.User) {
	if user.FailedLoginAttempts == 0 && user.LoginLockedUntil == nil && user.LoginLockoutCount == 0 {
		return
	}
	user.FailedLoginAttempts = 0
	user.LastFailedLoginAt = nil
	user.LoginLockedUntil = nil
	user.LoginLockoutCount = 0
	_, _ = c.storage.UpdateUser(ctx, user)
}

// UnlockUser clears a user's login-lockout state (admin action; audited). It does
// not change the account_state — a suspended account stays suspended.
func (c *KeyorixCore) UnlockUser(ctx context.Context, adminID, userID uint) error {
	if userID == 0 {
		return fmt.Errorf("user ID is required")
	}
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	user.FailedLoginAttempts = 0
	user.LastFailedLoginAt = nil
	user.LoginLockedUntil = nil
	user.LoginLockoutCount = 0
	user.UpdatedAt = c.now()
	if _, err := c.storage.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to unlock user: %w", err)
	}
	aid := adminID
	c.writeAuditEventFull(ctx, EventAccountUnlocked, &aid, nil, nil, "",
		fmt.Sprintf("user %d login lockout cleared by admin %d", userID, adminID))
	return nil
}

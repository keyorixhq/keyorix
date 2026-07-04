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
	"log"
	"sync"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
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

// loginFailureMuShards is the shard count for loginFailureMu (see service.go):
// enough to make same-shard collisions between two unrelated accounts rare under
// realistic concurrency, without the memory/complexity of a per-user sync.Map.
const loginFailureMuShards = 64

// loginFailureLock returns the shard of loginFailureMu serializing this user's
// failed-login accounting. Sharding by userID means a flood against one (even
// already-locked) account no longer blocks every other account's accounting
// behind a single process-wide lock.
func (c *KeyorixCore) loginFailureLock(userID uint) *sync.Mutex {
	return &c.loginFailureMu[userID%loginFailureMuShards]
}

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

// warnLockoutUnsupportedOnce logs a loud, ONE-TIME operator warning the first time the
// active storage backend proves it can never persist login-lockout accounting (#454) —
// as opposed to an ordinary transient storage error, which stays silent (the existing,
// intentional fail-open backstop behaviour). Mirrors warnRateLimitUnsupportedOnce
// (rate_limit.go, #452) for the identical class of gap on the other brute-force
// backstop. Safe for concurrent use; only the first call's message is emitted.
func (c *KeyorixCore) warnLockoutUnsupportedOnce() {
	c.loginLockoutUnsupportedWarnOnce.Do(func() {
		log.Printf("WARNING: per-account login lockout accounting is INERT under the " +
			"active storage backend (storage.type: remote) — UpdateLoginLockoutState has " +
			"no implementation to proxy to (the upstream server's PUT /api/v1/users/{id} " +
			"wire format cannot carry these fields), so every failed-login/clear write " +
			"fails and is silently skipped. There is NO per-account lockout protection for " +
			"this deployment unless the cluster-wide per-IP rate limiter is relied on " +
			"instead (see ADR-040 / #452). This warning is logged once per process; the " +
			"underlying gap persists for its lifetime.")
	})
}

// recordFailedLogin increments the user's failed-attempt counter (resetting it when
// the previous failure is older than the window) and locks the account once it
// reaches MaxAttempts. Best-effort persistence: a storage error must not change the
// "invalid credentials" outcome the caller returns.
//
// The read-increment-write runs inside a transaction over a freshly LockUserForUpdate'd
// row, under the user's loginFailureMu shard, so concurrent failures for the same
// account cannot lose an increment and let an attacker spend more than MaxAttempts
// guesses before the lock trips: the shard mutex serializes same-process callers for
// that account (and so the whole single-process SQLite case), and the FOR UPDATE row
// lock LockUserForUpdate takes on Postgres serializes across HA replicas. The
// passed-in user struct was loaded before the lock, so the authoritative current
// state is re-read inside the transaction.
func (c *KeyorixCore) recordFailedLogin(ctx context.Context, user *models.User) {
	if !c.loginLockout.Enabled {
		return
	}
	uid := user.ID
	now := c.now()

	mu := c.loginFailureLock(uid)
	mu.Lock()
	defer mu.Unlock()

	var locked bool
	var lockedUntil time.Time
	var lockoutNum int

	err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		u, err := tx.LockUserForUpdate(ctx, uid)
		if err != nil {
			return err
		}
		// Already within an active lockout: don't escalate. The Login gate refuses to
		// process a password while locked, so reaching here means this caller loaded the
		// user before the lock was set (a concurrent burst). Counting it would re-trip the
		// lock with exponential backoff and stretch a single burst into a much longer lock.
		if u.LoginLockedUntil != nil && now.Before(*u.LoginLockedUntil) {
			return nil
		}
		// A stale failure (older than the window) starts a fresh count.
		if u.LastFailedLoginAt != nil && now.Sub(*u.LastFailedLoginAt) > c.loginLockout.Window {
			u.FailedLoginAttempts = 0
		}
		u.FailedLoginAttempts++
		u.LastFailedLoginAt = &now

		tripped := u.FailedLoginAttempts >= c.loginLockout.MaxAttempts
		if tripped {
			u.LoginLockoutCount++
			until := now.Add(c.loginLockout.cooldownFor(u.LoginLockoutCount))
			u.LoginLockedUntil = &until
			u.FailedLoginAttempts = 0 // window counter resets; the lock now gates
		}
		// #454: persist via the narrow UpdateLoginLockoutState, not the generic
		// UpdateUser — RemoteStorage can never express these columns in its wire format,
		// so it always returns storage.ErrUnsupportedByBackend here. Unlike
		// setAccountState/UpdateSCIMUser's hard fail, lockout accounting is a passive
		// backstop (#452's identical rationale for the per-IP rate limiter): log once and
		// fail open, rather than erroring the caller (which would otherwise refuse every
		// login attempt for a storage backend that can never persist this).
		if err := tx.UpdateLoginLockoutState(ctx, uid, u.FailedLoginAttempts, u.LastFailedLoginAt, u.LoginLockedUntil, u.LoginLockoutCount); err != nil {
			if isUnsupportedByBackend(err) {
				c.warnLockoutUnsupportedOnce()
				return nil
			}
			return err
		}
		// Reflect the persisted lockout fields back onto the caller's struct (it was
		// loaded before the lock), without clobbering preloaded associations. Only reached
		// when the write above actually committed, so a struct mutated in memory always
		// matches what was (or, on the unsupported-backend path above, was not) persisted.
		user.FailedLoginAttempts = u.FailedLoginAttempts
		user.LastFailedLoginAt = u.LastFailedLoginAt
		user.LoginLockedUntil = u.LoginLockedUntil
		user.LoginLockoutCount = u.LoginLockoutCount
		if tripped {
			locked, lockedUntil, lockoutNum = true, *u.LoginLockedUntil, u.LoginLockoutCount
		}
		return nil
	})
	if err != nil {
		return // best-effort: a storage error must not change the caller's outcome
	}

	// Emit the lock audit only after the transaction commits, so a rolled-back lock is
	// never logged.
	if locked {
		c.writeAuditEventFull(ctx, EventAccountLocked, &uid, nil, nil, "",
			fmt.Sprintf("account %d locked until %s after repeated failed logins (lockout #%d)",
				uid, lockedUntil.UTC().Format(time.RFC3339), lockoutNum))
	}
}

// checkLockAndClearLoginFailures re-checks the account's lock state and, if not
// locked, clears any accumulated failure state — both under the SAME
// serialization (the user's loginFailureMu shard, plus the Postgres FOR UPDATE
// row lock LockUserForUpdate takes) that recordFailedLogin uses. This closes the
// TOCTOU gap between a caller's pre-verification snapshot check (loginLocked,
// evaluated against a user row read before the slow credential check — bcrypt, a
// TOTP/recovery-code check, or a WebAuthn assertion) and minting a session:
// without re-checking here, a concurrent burst of failed attempts against the
// same account could trip the lock AFTER a request already passed the snapshot
// check but BEFORE it mints a session, letting that request's otherwise-valid
// credential succeed against an account that should already be locked.
//
// Returns an error (the same "account temporarily locked" message the snapshot
// check uses) when the account is found to be locked; the caller MUST refuse the
// login rather than mint a session. Also returns an error — failing closed — if
// the lock state cannot be verified (a storage error), rather than falling back
// to the caller's stale snapshot. When the lockout feature is disabled this is
// equivalent to clearLoginFailures. Shared by every login path that reaches a
// session mint after passing the lockout gate: password (Login), TOTP/recovery
// (VerifyMFALogin), and WebAuthn (FinishWebAuthnLogin /
// FinishWebAuthnPasswordlessLogin) — recordFailedLogin feeds the same counter
// from all of them, so the recheck must cover all of them too.
//
// #454: when clearing accumulated failures, a backend that can never persist the
// clear (RemoteStorage) is treated the same as "nothing to clear" — logged once via
// warnLockoutUnsupportedOnce and NOT surfaced as the fail-closed "unable to verify"
// error, since lockout is a backstop, not the primary auth boundary (mirrors #452's
// identical fail-open-but-loud tradeoff for the per-IP rate limiter). A genuine
// transient storage error is unaffected and still fails closed below.
func (c *KeyorixCore) checkLockAndClearLoginFailures(ctx context.Context, user *models.User) error {
	if !c.loginLockout.Enabled {
		c.clearLoginFailures(ctx, user)
		return nil
	}
	uid := user.ID

	mu := c.loginFailureLock(uid)
	mu.Lock()
	defer mu.Unlock()

	var lockErr error
	err := c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		u, err := tx.LockUserForUpdate(ctx, uid)
		if err != nil {
			return err
		}
		if u.LoginLockedUntil != nil && c.now().Before(*u.LoginLockedUntil) {
			// A concurrent burst tripped the lock after our caller's pre-verification
			// snapshot but before we reached here — reflect the authoritative state
			// back onto the caller's struct and refuse.
			user.LoginLockedUntil = u.LoginLockedUntil
			user.LoginLockoutCount = u.LoginLockoutCount
			lockErr = fmt.Errorf("account temporarily locked due to repeated failed logins; try again later")
			return nil
		}
		if u.FailedLoginAttempts == 0 && u.LoginLockedUntil == nil && u.LoginLockoutCount == 0 {
			return nil // nothing to clear
		}
		if err := tx.UpdateLoginLockoutState(ctx, uid, 0, nil, nil, 0); err != nil {
			if isUnsupportedByBackend(err) {
				c.warnLockoutUnsupportedOnce()
				return nil // can't clear counters on this backend; fail OPEN (not locked), not closed
			}
			return err
		}
		user.FailedLoginAttempts = 0
		user.LastFailedLoginAt = nil
		user.LoginLockedUntil = nil
		user.LoginLockoutCount = 0
		return nil
	})
	if err != nil {
		// Unable to verify the current lock state — fail closed. Silently falling
		// back to "not locked" here would reopen exactly the snapshot-trust gap
		// this function exists to close.
		return fmt.Errorf("unable to verify account lock state, please try again")
	}
	return lockErr
}

// clearLoginFailures resets the lockout state after a successful authentication.
// It writes only when there is something to clear, so the happy path adds no extra
// write on every login. #454: persists via UpdateLoginLockoutState, not the generic
// UpdateUser, so a backend that can never express these columns (RemoteStorage) is
// visibly reported (a one-time operator warning) instead of silently no-op'd.
func (c *KeyorixCore) clearLoginFailures(ctx context.Context, user *models.User) {
	if user.FailedLoginAttempts == 0 && user.LoginLockedUntil == nil && user.LoginLockoutCount == 0 {
		return
	}
	if err := c.storage.UpdateLoginLockoutState(ctx, user.ID, 0, nil, nil, 0); err != nil {
		if isUnsupportedByBackend(err) {
			c.warnLockoutUnsupportedOnce()
		}
		return
	}
	user.FailedLoginAttempts = 0
	user.LastFailedLoginAt = nil
	user.LoginLockedUntil = nil
	user.LoginLockoutCount = 0
}

// UnlockUser clears a user's login-lockout state (admin action; audited). It does
// not change the account_state — a suspended account stays suspended.
//
// #484: persists via the same narrow UpdateLoginLockoutState primitive #454 already
// established for the automatic clear paths (clearLoginFailures /
// checkLockAndClearLoginFailures) — not the generic UpdateUser, which silently no-ops
// every one of these columns under storage.type: remote (they have no field in the
// wire format at all). UnlockUser clears the exact same four columns those callers
// do, just admin-triggered instead of triggered by a successful login, so it gets the
// identical treatment: lockout accounting is a passive backstop, not an explicit
// security directive (unlike account_state), so a backend that can never persist the
// clear fails OPEN (logged once via warnLockoutUnsupportedOnce) rather than erroring
// the admin — the worst case is the lock merely expires on its own cooldown instead of
// being cleared early.
func (c *KeyorixCore) UnlockUser(ctx context.Context, adminID, userID uint) error {
	if userID == 0 {
		return fmt.Errorf("user ID is required")
	}
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	if err := c.storage.UpdateLoginLockoutState(ctx, userID, 0, nil, nil, 0); err != nil {
		if !isUnsupportedByBackend(err) {
			return fmt.Errorf("failed to unlock user: %w", err)
		}
		c.warnLockoutUnsupportedOnce()
	} else {
		user.FailedLoginAttempts = 0
		user.LastFailedLoginAt = nil
		user.LoginLockedUntil = nil
		user.LoginLockoutCount = 0
	}
	aid := adminID
	c.writeAuditEventFull(ctx, EventAccountUnlocked, &aid, nil, nil, "",
		fmt.Sprintf("user %d login lockout cleared by admin %d", userID, adminID))
	return nil
}

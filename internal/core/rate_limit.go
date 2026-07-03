// rate_limit.go — cluster-wide login brute-force rate limiting (ADR-040). A
// windowed count of failed attempts per IP, persisted in the DB so the limit holds
// across HA replicas (the old limiter was a per-process in-memory map). Rate
// limiting is a backstop on top of the real password/passkey checks, so a storage
// error fails OPEN (allow) rather than locking everyone out on a DB hiccup.
package core

import (
	"context"
	"time"
)

const (
	// LoginMaxAttempts is the failed-attempt budget per IP within LoginWindow.
	LoginMaxAttempts = 10
	// LoginWindow is the sliding window over which attempts are counted.
	LoginWindow = 15 * time.Minute
)

// IsLoginRateLimited reports whether an IP has reached the failed-login budget
// within the window. Fails open (false) on an empty IP or a storage error.
func (c *KeyorixCore) IsLoginRateLimited(ctx context.Context, ip string) bool {
	if ip == "" {
		return false
	}
	n, err := c.storage.CountRecentLoginAttempts(ctx, ip, c.now().Add(-LoginWindow))
	if err != nil {
		return false
	}
	return n >= LoginMaxAttempts
}

// RecordFailedLogin records a failed authentication attempt from an IP.
// Best-effort: a storage error does not block the response path.
func (c *KeyorixCore) RecordFailedLogin(ctx context.Context, ip string) {
	if ip == "" {
		return
	}
	_ = c.storage.RecordLoginAttempt(ctx, ip, c.now())
}

// PruneLoginAttempts removes attempts older than the window; called by the
// maintenance sweep. Returns the number removed.
func (c *KeyorixCore) PruneLoginAttempts(ctx context.Context) (int64, error) {
	return c.storage.PruneLoginAttempts(ctx, c.now().Add(-LoginWindow))
}

// passwordResetRateLimitPrefix namespaces password-reset attempts within the
// SAME LoginAttempt table the login rate limiter uses (ADR-040), so a
// password-reset flood budget is tracked per-IP separately from — but reuses
// the identical cluster-wide, DB-backed limiter as — failed login attempts.
// POST /auth/password-reset (#249) is fully unauthenticated and had zero
// rate-limiting of any kind before this; composing the key this way (rather
// than a second table/migration) matches the codebase's existing convention
// for "per-IP request budget" and needs no schema change.
const passwordResetRateLimitPrefix = "pwreset:"

const (
	// PasswordResetMaxAttempts is the request budget per IP within
	// PasswordResetWindow. Deliberately tighter than LoginMaxAttempts: each
	// request potentially triggers a real outbound email, so the budget is a
	// mail-bombing defense, not just a guess-throttle.
	PasswordResetMaxAttempts = 5
	// PasswordResetWindow is the sliding window over which attempts are counted.
	PasswordResetWindow = 15 * time.Minute
)

// IsPasswordResetRateLimited reports whether an IP has reached the
// password-reset request budget within the window. Fails open (false) on an
// empty IP or a storage error — this is a defense-in-depth backstop on top of
// the per-email checkResendThrottle (ADR-028), not the sole abuse control.
func (c *KeyorixCore) IsPasswordResetRateLimited(ctx context.Context, ip string) bool {
	if ip == "" {
		return false
	}
	n, err := c.storage.CountRecentLoginAttempts(ctx, passwordResetRateLimitPrefix+ip, c.now().Add(-PasswordResetWindow))
	if err != nil {
		return false
	}
	return n >= PasswordResetMaxAttempts
}

// RecordPasswordResetAttempt records a password-reset request from an IP.
// Unlike RecordFailedLogin (recorded only on a WRONG password), this is
// recorded on EVERY request regardless of outcome: the endpoint always returns
// success (enumeration-safe) and never signals which email is registered, so
// the request itself — not a distinguishable "failure" — is the abuse signal
// to budget against. Best-effort: a storage error does not block the response.
func (c *KeyorixCore) RecordPasswordResetAttempt(ctx context.Context, ip string) {
	if ip == "" {
		return
	}
	_ = c.storage.RecordLoginAttempt(ctx, passwordResetRateLimitPrefix+ip, c.now())
}

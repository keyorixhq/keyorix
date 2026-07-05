// rate_limit.go — cluster-wide login brute-force rate limiting (ADR-040). A
// windowed count of failed attempts per IP, persisted in the DB so the limit holds
// across HA replicas (the old limiter was a per-process in-memory map). Rate
// limiting is a backstop on top of the real password/passkey checks, so a storage
// error fails OPEN (allow) rather than locking everyone out on a DB hiccup.
//
// #452 (closed): RemoteStorage.CountRecentLoginAttempts/RecordLoginAttempt/
// PruneLoginAttempts used to have no server endpoint to proxy to at all when the
// server itself ran storage.type: remote in a chained deployment, so the fail-open
// below was permanent and total for the life of the process rather than an
// occasional transient degradation. That is now fixed — see
// internal/storage/store/remote_login_attempts.go and
// server/http/handlers/login_attempts_proxy.go: RemoteStorage genuinely proxies to a
// real upstream counter, the same one ADR-040's own /auth/login handler uses.
//
// The storage.ErrUnsupportedByBackend detection below is kept as defense in depth
// for any FUTURE backend (or storage-layer change) that genuinely cannot satisfy
// this call — a plain transient storage error (DB hiccup, network blip) still fails
// open silently by design (an acceptable, temporary degradation), but a backend that
// can NEVER satisfy the call is worth a loud, ONE-TIME operator-visible warning
// instead (not per-request log spam, and not blocking login — this is still a
// backstop, not the auth boundary).
package core

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

const (
	// LoginMaxAttempts is the failed-attempt budget per IP within LoginWindow.
	LoginMaxAttempts = 10
	// LoginWindow is the sliding window over which attempts are counted.
	LoginWindow = 15 * time.Minute
)

// warnRateLimitUnsupportedOnce logs a loud, ONE-TIME operator warning the first
// time the active storage backend proves it can never satisfy
// CountRecentLoginAttempts (originally #452; RemoteStorage itself no longer hits
// this — see rate_limit.go's file-level doc comment) — as opposed to an ordinary
// transient error, which stays silent (that's the existing, intentional fail-open
// backstop behaviour). Safe for concurrent use; only the first call's message is
// emitted.
func (c *KeyorixCore) warnRateLimitUnsupportedOnce() {
	c.rateLimitUnsupportedWarnOnce.Do(func() {
		log.Printf("WARNING: login/password-reset rate limiting is INERT under the " +
			"active storage backend — CountRecentLoginAttempts has no implementation " +
			"to proxy to, so every call fails open. There is NO cluster-wide " +
			"brute-force login throttle for this deployment unless per-account lockout " +
			"is separately enabled (see docs on login lockout / ADR-025). This warning " +
			"is logged once per process; the underlying gap persists for its lifetime.")
	})
}

// isUnsupportedByBackend reports whether err indicates the active storage
// backend has no implementation for the operation at all (permanent, not a
// transient failure worth staying silent about).
func isUnsupportedByBackend(err error) bool {
	return errors.Is(err, storage.ErrUnsupportedByBackend)
}

// IsLoginRateLimited reports whether an IP has reached the failed-login budget
// within the window. Fails open (false) on an empty IP or a storage error.
func (c *KeyorixCore) IsLoginRateLimited(ctx context.Context, ip string) bool {
	if ip == "" {
		return false
	}
	n, err := c.storage.CountRecentLoginAttempts(ctx, ip, c.now().Add(-LoginWindow))
	if err != nil {
		if isUnsupportedByBackend(err) {
			c.warnRateLimitUnsupportedOnce()
		}
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
		if isUnsupportedByBackend(err) {
			c.warnRateLimitUnsupportedOnce()
		}
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

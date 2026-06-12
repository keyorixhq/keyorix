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

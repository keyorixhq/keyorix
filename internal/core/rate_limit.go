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
	"fmt"
	"log"
	"net"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// CanonicalIP returns addr's IP address in canonical (net.IP.String()) form,
// stripping any ":port" suffix first when present — via net.SplitHostPort,
// which correctly handles bracketed IPv6 ("[::1]:8080") as well as plain
// "host:port" forms, falling back to treating addr itself as a bare
// host/IP when SplitHostPort finds no port (including a bare, unbracketed
// IPv6 address, which SplitHostPort always rejects as ambiguous). If the
// resulting host doesn't parse as an IP at all, it is returned unchanged.
//
// #G20: a rate-limit key built from an uncanonicalized source string lets
// trivially different textual representations of the SAME source — an
// alternate compressed/expanded IPv6 form, a bracketed vs. bare address, a
// fresh ephemeral TCP port from simply reconnecting — land in different
// buckets, defeating the shared budget entirely and growing the limiter map
// without bound. Used as the single shared canonicalization point for every
// per-source rate limiter in this codebase (HTTP login/password-reset/SSO
// limiters here, the gRPC per-principal limiter's IP fallback, and the HTTP
// handlers that derive a rate-limit key from r.RemoteAddr directly).
func CanonicalIP(addr string) string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

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
	ip = CanonicalIP(ip)
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
	_ = c.storage.RecordLoginAttempt(ctx, CanonicalIP(ip), c.now())
}

// PruneLoginAttempts removes login/password-reset rate-limit rows older than
// `before`. `before` is clamped so the effective cutoff can never be LATER
// than `now - LoginWindow` — the maintenance sweep's own invariant (server/
// main.go always calls this with a zero `before`, which resolves to exactly
// that cutoff) — so a caller can only narrow the deletion window, never widen
// it into an unbounded wipe. This is the sole enforcement point for the
// bound: server/http/handlers/login_attempts_proxy.go's PruneLoginAttemptsProxy
// (the only other caller, decoding an attacker-influenced `before` from an
// HTTP request body) routes through this method rather than calling
// c.storage.PruneLoginAttempts directly, specifically so it cannot bypass the
// clamp (CORE-RATE-003: an unbounded `before` let any principal holding
// system.write wipe the entire login_attempts table on demand — every IP's
// failed-attempt count and the only record a brute-force campaign was ever
// attempted from any address — with no trace).
//
// actorID is the acting principal's user ID (0 for the scheduler / a
// non-user principal — e.g. a node/machine credential — matching
// writeRBACAudit's "0 = no authenticated principal" convention; the
// context's ActorType tag, set by the caller, still distinguishes
// system/machine/user attribution on the emitted event). Returns the number
// of rows removed. When anything is actually removed, emits a
// `data.login_attempts_pruned` audit event recording the actor, row count,
// and effective cutoff — mirroring PurgeExpiredSoftDeletes/
// PurgeExpiredComplianceRecords, which this primitive previously had no
// equivalent of at all.
func (c *KeyorixCore) PruneLoginAttempts(ctx context.Context, before time.Time, actorID uint) (int64, error) {
	cutoff := c.now().Add(-LoginWindow)
	if !before.IsZero() && before.Before(cutoff) {
		cutoff = before
	}

	n, err := c.storage.PruneLoginAttempts(ctx, cutoff)
	if err != nil {
		return n, err
	}
	if n > 0 {
		var actor *uint
		if actorID != 0 {
			actor = &actorID
		}
		c.writeAuditEvent(ctx, "data.login_attempts_pruned", actor, nil,
			fmt.Sprintf("login-attempts prune removed %d row(s) older than %s", n, cutoff.UTC().Format(time.RFC3339)))
	}
	return n, nil
}

// passwordResetRateLimitPrefix namespaces password-reset attempts within the
// SAME LoginAttempt table the login rate limiter uses (ADR-040), so a
// password-reset flood budget is tracked per-IP separately from — but reuses
// the identical cluster-wide, DB-backed limiter as — failed login attempts.
// POST /auth/password-reset (#249) is fully unauthenticated and had zero
// rate-limiting of any kind before this; composing the key this way (rather
// than a second table/migration) matches the codebase's existing convention
// for "per-IP request budget" and needs no schema change.
const passwordResetRateLimitPrefix = "pwreset:" // NOSONAR

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
	n, err := c.storage.CountRecentLoginAttempts(ctx, passwordResetRateLimitPrefix+CanonicalIP(ip), c.now().Add(-PasswordResetWindow))
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
	_ = c.storage.RecordLoginAttempt(ctx, passwordResetRateLimitPrefix+CanonicalIP(ip), c.now())
}

// ssoRateLimitPrefix namespaces SSO/SAML login-initiation attempts within the
// SAME LoginAttempt table (ADR-040), mirroring passwordResetRateLimitPrefix.
// #G82: BeginSSO/BeginSAML are both fully unauthenticated and each write a
// SSOLoginState row per call with no rate limit of any kind — an unbounded
// flood grows that table without limit and, since every SSOLoginState carries
// a fresh CSRF-protecting state/nonce, also churns through randomness/storage
// for no legitimate purpose. Shared between SSO and SAML since both are the
// same "pre-login state write" abuse shape against the same table.
const ssoRateLimitPrefix = "sso:" // NOSONAR

// SSOBeginMaxAttempts is the request budget per IP within SSOBeginWindow.
const SSOBeginMaxAttempts = 20

// SSOBeginWindow is the sliding window over which attempts are counted.
const SSOBeginWindow = 15 * time.Minute

// IsSSOBeginRateLimited reports whether an IP has reached the SSO/SAML
// login-initiation budget within the window. Fails open (false) on an empty
// IP or a storage error, matching the login/password-reset limiters' backstop
// (not the sole abuse control) design.
func (c *KeyorixCore) IsSSOBeginRateLimited(ctx context.Context, ip string) bool {
	if ip == "" {
		return false
	}
	n, err := c.storage.CountRecentLoginAttempts(ctx, ssoRateLimitPrefix+CanonicalIP(ip), c.now().Add(-SSOBeginWindow))
	if err != nil {
		if isUnsupportedByBackend(err) {
			c.warnRateLimitUnsupportedOnce()
		}
		return false
	}
	return n >= SSOBeginMaxAttempts
}

// RecordSSOBeginAttempt records an SSO/SAML login-initiation request from an
// IP. Recorded on every call regardless of outcome (unknown-provider or
// success) — the request itself is the abuse signal. Best-effort: a storage
// error does not block the response.
func (c *KeyorixCore) RecordSSOBeginAttempt(ctx context.Context, ip string) {
	if ip == "" {
		return
	}
	_ = c.storage.RecordLoginAttempt(ctx, ssoRateLimitPrefix+CanonicalIP(ip), c.now())
}

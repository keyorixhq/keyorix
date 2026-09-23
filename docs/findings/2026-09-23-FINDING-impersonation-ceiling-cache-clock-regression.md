# FINDING: `cachedImpersonationCeiling` extends a stale ALLOW past its TTL on a backward clock step

**Date:** 2026-09-23
**Component:** `internal/core/authz.go` (`cachedImpersonationCeiling`), reached
from `internal/core/impersonation.go`'s `ReauthorizeImpersonation` — called by
`ValidateSessionToken` (`auth.go`, every request against an impersonation
session) and `StreamAuditLogs`'s re-auth ticker (`server/grpc/services/audit_service.go`, #108).
**Status:** **Fixed**, this PR. Proving test:
`TestReauthorizeImpersonation_CeilingCacheClockSteppedBackward_RevokedStaysDenied`
(`internal/core/impersonation_ceiling_cache_clock_regression_test.go`).
**Severity: Medium** (requires a server-side clock event, not attacker-controlled input).

## Summary

`cachedImpersonationCeiling` caches the result of `requireStillAuthorizedToImpersonate`
(IMP-001) for `ceilingCacheTTL` (60s), keyed by `actorID:targetID`. Both the
cache write (`expiresAt: c.now().Add(ceilingCacheTTL)`) and the cache read
(`c.now().Before(entry.expiresAt)`) used raw `c.now()` — real wall-clock time,
with no protection against the clock regressing.

`ReauthorizeImpersonation` is the mechanism that is supposed to end an active
impersonation session within one re-auth cycle after the admin's
`users.impersonate` grant is revoked, or their authority ceiling relative to
the target drops (MT-007/#G05) — mirroring how every other credential-expiry
check on the same request path (session `ExpiresAt`/`AbsoluteExpiresAt`,
checked immediately before this one in `ValidateSessionToken`) is expected to
behave.

If the server's wall clock steps backward after a verdict is cached — an NTP
correction, or an operator manually resetting a drifted clock — every
subsequent raw `c.now()` read can land before the cached entry's `expiresAt`
again, even though real elapsed time has already exceeded the 60s TTL
(possibly by a wide margin, watched from the process's actual passage of
time). The stale cached verdict — including a stale ALLOW for an admin whose
`users.impersonate` grant was revoked, or who no longer outranks the target —
keeps being returned for as long as the clock stays behind.

This is the same clock-regression hazard already fixed for session refresh
(`checkSessionRefreshClockNotRegressed`, #1653), RBAC permission resolution
(`rbacEffectiveNow`), Connect/share validity, and the session-credential-expiry
family itself (`authEffectiveNow`, which `cachedImpersonationCeiling` sits
immediately downstream of in `ValidateSessionToken`) — this one check in that
family was missed.

## Fix

Swap both the cache write and the cache read from raw `c.now()` to
`c.authEffectiveNow()` — the same watermark-clamped clock `ValidateSessionToken`
already calls twice (for `session.ExpiresAt`/`AbsoluteExpiresAt`) immediately
before reaching `ReauthorizeImpersonation`, in the same request. No new
watermark mechanism: this reuses the existing `authTokenClockWatermark`
(`service.go`) rather than adding a dedicated one for one more check.

```go
if v, ok := c.impersonationCeilingCache.Load(key); ok {
	if entry := v.(ceilingCacheEntry); c.authEffectiveNow().Before(entry.expiresAt) {
		return entry.err
	}
}
err := c.requireStillAuthorizedToImpersonate(ctx, actorID, targetID)
c.impersonationCeilingCache.Store(key, ceilingCacheEntry{err: err, expiresAt: c.authEffectiveNow().Add(ceilingCacheTTL)})
```

## Reproduction / proving test

`TestReauthorizeImpersonation_CeilingCacheClockSteppedBackward_RevokedStaysDenied`
constructs the exploit deterministically, with an injected clock (no real
sleeps):

1. At `T0`, `ReauthorizeImpersonation` succeeds (admin holds
   `users.impersonate`, outranks target) — cached with `expiresAt = T0+60s`,
   warming the shared watermark to `T0`.
2. Genuine forward progress elsewhere in the process is simulated by calling
   `c.authEffectiveNow()` directly with the clock at `T0+120s` (past the
   cache's TTL) — warming the watermark to `T0+120s`, without touching the
   impersonation cache entry itself.
3. The admin's `users.impersonate` grant is revoked (mock stub swapped for
   the next consumed call).
4. The clock is stepped **backward** to `T0+30s` — nominally still inside the
   cache's 60s window if read naively — and `ReauthorizeImpersonation` is
   called again for the same pair.

## Red-proof

Reverting `authz.go` to raw `c.now()` (temporarily, not committed) makes the
proving test fail exactly as expected: `Error: An error is expected but got
nil` — step 4 returns the stale cached ALLOW instead of the revocation error.
Restoring the `authEffectiveNow()` fix returns the test to green. Verified
directly on this branch before opening the PR.

## Verification

`go vet ./...`, `go build ./...`, `golangci-lint run ./internal/core/...`
(0 issues) all clean. `go test ./internal/core/...` green (10.7s). Also ran
`server/grpc/services`' impersonation/audit-stream re-auth tests
(`TestReauthorizeAuditStream_*`, `TestAuditService_StreamAuditLogs_*`) —
all pass unaffected, since `authEffectiveNow()` behaves identically to
`c.now()` under normal (non-regressing) clock conditions.

## Severity rationale

Rated **Medium**, not Critical: exploitation requires a server-side clock
event (NTP step-correction or an operator/ops time change), not attacker-
controlled input — an attacker cannot trigger this on demand. But when it
does occur, the impact is real: a revoked impersonation authority, or an
admin who has been demoted below the target's rank, continues to be honored
past the intended 60s re-auth ceiling, for as long as the clock stays behind
— on both the per-request session path and the gRPC audit-stream re-auth
ticker.

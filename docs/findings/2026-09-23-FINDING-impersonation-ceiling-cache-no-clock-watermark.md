# FINDING: impersonation privilege-ceiling cache had no backward-clock-jump protection

**Date:** 2026-09-23
**Component:** `internal/core/authz.go` (`cachedImpersonationCeiling`,
`ReauthorizeImpersonation`'s ceiling check, IMP-001/MT-007).
**Status:** **Fixed**, same PR. Proving tests:
`TestCachedImpersonationCeiling_ClockSteppedBackward_StaleAllowIsRechecked`,
`TestImpersonationCeilingEffectiveNow_ClampsBackwardReadingToWatermark`
(`internal/core/impersonation_ceiling_clock_regression_test.go`).
**Severity: Low.** Requires an operator-level or NTP-less backward clock step
on the host running Keyorix, not attacker-controlled input; narrows an
existing 60s cache-staleness window rather than opening a new authorization
bypass class.

## Summary

Found during the #1983 clock-jump-under-fuzzing investigation (inventorying
every time source behind an authorization/expiry decision in this codebase):
`cachedImpersonationCeiling` is a `sync.Map`-backed, 60-second TTL cache of
`requireStillAuthorizedToImpersonate`'s result, keyed by `"actorID:targetID"`,
consulted by `ReauthorizeImpersonation` on **every** authenticated request
made under an active impersonation session (`ValidateSessionToken`) and by
`StreamAuditLogs`' dedicated gRPC re-auth ticker. It is the ongoing
"is this impersonation still authorized" check MT-007/#G05 added so that
revoking an admin's `users.impersonate` permission, or promoting the
impersonated target's own authority, ends the session within one re-auth
cycle instead of remaining valid for the rest of its TTL.

Every other TTL-based cache or permission-resolution check in this same file
already carries an in-memory monotonic watermark protecting it against a host
clock stepped backward: `authTokenClockWatermark` (sessions/PATs/machine
tokens/MFA step-up, `auth.go`), `shareClockWatermark` (`permissions.go`),
`connectClockWatermark` (`connect.go`). `cachedImpersonationCeiling` was the
one exception — its cache-hit check compared a bare `c.now()` directly
against the entry's `expiresAt`:

```go
if entry := v.(ceilingCacheEntry); c.now().Before(entry.expiresAt) {
    return entry.err
}
```

A host clock stepped backward after a verdict was cached makes `c.now()` read
earlier than it did at write time, so `.Before(entry.expiresAt)` stays true
for **longer** than the intended 60s — a stale cached result, including a
stale **ALLOW**, is served past its real-time TTL. If the cached verdict was
"allowed" and the admin's `users.impersonate` was revoked (or the target was
promoted) during that extended window, the fresh re-check that should have
caught it is skipped, and the stale allow keeps authorizing requests — widening
the exact MT-007 exposure window this cache exists to bound, precisely during
the failure mode (an operator or NTP-less clock correction stepping the host
clock back "while the server keeps running") every sibling watermark in this
file was already built to defend against.

## Interaction with PR #1979

Checked before writing the fix (per this investigation's own finding that a
Go call graph or file overlap isn't proof of a real interaction): PR #1979
(open, `fix/system-proxy-sweep-g3`, base `main`) touches `internal/core/authz.go`,
but its entire diff is `requireGranterHoldsRolePermissions`
(the `roles.assign`-baseline check, ~line 681 on `main`) and the new
system-proxy relay admin-tier ceiling (~line 786 onward) — the F6 sweep. No
line range, symbol, or field it touches overlaps
`ceilingCacheEntry`/`ceilingCacheTTL`/`cachedImpersonationCeiling` (lines
474–491) or anything added to `service.go` by this fix. No interaction
expected regardless of merge order; this PR's diff should apply/rebase
cleanly onto #1979 either way.

## Fix

Adds `impersonationCeilingClockWatermark`
(`KeyorixCore`, `service.go`) and `impersonationCeilingEffectiveNow`
(`authz.go`), mirroring `authEffectiveNow`/`shareEffectiveNow`'s shape
exactly: `c.now().UTC()`, clamped forward-only against the watermark, `.UTC()`
stripping any monotonic clock reading so a backward wall-clock step is
actually detectable (same rationale `authEffectiveNow`'s doc comment gives).
**CLAMPs rather than refuses** — matching every sibling watermark in this
file, not `sessionRefreshWatermark`/`accessRequestApprovalWatermark`'s
refuse-outright shape — because this check runs on every authenticated
request under an active impersonation session (a pervasive read path), so
refusing outright the moment a regression is detected would turn a narrow
clock-integrity concern into an outage for every impersonation session,
process-wide, until the clock recovers.

`cachedImpersonationCeiling`'s two `c.now()` call sites (the cache-hit check
and the write of a fresh entry's `expiresAt`) both now go through
`impersonationCeilingEffectiveNow()` instead.

### Red-proof

Reverted the cache-hit check back to bare `c.now()` (scratch edit, not in
this diff) — `TestCachedImpersonationCeiling_ClockSteppedBackward_StaleAllowIsRechecked`
failed: a cached ALLOW seeded at `baseline` with the watermark independently
warmed to `baseline+90s` (simulating a reading this process had already
legitimately observed) was still trusted after `c.now()` was stepped back to
`baseline+30s`, even though the underlying authority mock was set up to
return "revoked" — the fresh re-check never ran. Restored; full
`internal/core` suite green afterward.

## What this does NOT cover

- **Invalidation on "end impersonation" or a role change is still TTL-only.**
  Ending an impersonation session deletes the session row but never touches
  `impersonationCeilingCache` — harmless today (nothing else consults a stale
  entry for a pair whose session no longer exists), but worth naming: this
  fix closes the backward-clock-jump gap specifically, not "make the cache
  invalidate eagerly on every event that should logically invalidate it."
- **Process-restart reset.** Like every other in-memory watermark in this
  file (`secretExpiryWatermark`'s doc comment names this explicitly), the
  watermark resets to zero on process restart — an attacker able to both step
  the clock back AND restart the process defeats it. Same residual risk,
  same "named rather than hidden" treatment as the precedent this fix
  follows, not a new limitation this fix introduces.
- **The four watermark mechanisms in this file remain separate, unmerged
  constructs** (`authTokenClockWatermark`, `shareClockWatermark`,
  `connectClockWatermark`, and now `impersonationCeilingClockWatermark`,
  plus `consumeClockWatermark` in the storage layer). Unifying them into one
  process-level effective-now is a security-policy question, not a bug fix —
  tracked separately as a proposed ADR, not implemented here.

# FINDING: Dynamic-secret lease renewal and the expiry sweep have no anti-rollback watermark

**Date:** 2026-09-27
**Component:** `internal/core/dynamic_secrets.go` (`RenewLease`, `RevokeExpiredLeases`).
**Status:** Confirmed reproducible. Fix tracked as a separate `fix(security)` PR
(mirrors `checkSessionRefreshClockNotRegressed`, #1632/#1653).
**Severity:** Low-Medium. Requires the ability to step the server host's wall
clock backward (an operator action, a bad NTP correction, or host-level
compromise) — the same threat model the #1983 clock-jump investigation
covers for every other expiring-credential type in this codebase.

## Background

The #1983 investigation added an in-process anti-rollback watermark
(`authEffectiveNow`, `checkSessionRefreshClockNotRegressed`,
`shareEffectiveNow`, `checkAccessRequestApprovalClockNotRegressed`) to every
other expiring-credential/time-gated decision in `internal/core`, specifically
so that a backward host wall-clock step cannot un-expire something this
process has already correctly observed as expired. `EffectiveNow`'s own doc
comment (`service.go`) explicitly named dynamic secrets as the one exception,
deferred as "a separate, larger change, out of scope."

FUZZ-MECH M2's `FuzzClockJumpNeverAuthorizesExpired`
(`internal/core/clock_fuzz_test.go`) targets exactly this class of gap
across sessions, PATs, and dynamic-secret leases. Sessions and PATs are correctly protected (oracle 2 passes for both).
Dynamic-secret leases are not — reproduced deterministically by
`TestDynamicSecretLeaseRenewal_KnownGap_ClockRollback` in the same file.

## Reproduction

1. Issue a dynamic-secret lease with a 60s TTL at `T0`.
2. Advance the clock to `T0+61s` (past expiry). `RenewLease` correctly
   refuses ("lease has expired; issue a new lease instead") — the ordinary
   case works.
3. Step the clock BACK to `T0+59s` (before expiry again, simulating a host
   wall-clock rollback). `RenewLease` succeeds — it has no memory of having
   already observed this lease as expired one step earlier, because its
   check (`!c.now().Before(lease.ExpiresAt)`, `dynamic_secrets.go:880`) reads
   the bare injected clock with no watermark.
4. Separately: the background sweep (`RevokeExpiredLeases`, called with a
   `before` cutoff the caller — the scheduler in `server/main.go` — computes
   from its own clock reading) can miss an already-expired lease entirely if
   that caller's own clock reading regressed between two sweep ticks, since
   `RevokeExpiredLeases` uses `before` exactly as given, with no floor.

## Impact

Bounded: exploiting this requires the ability to step the SERVER HOST's own
wall clock backward — not a remote attacker capability. Within that model,
an actor who can already issue/renew leases on a config (already holds
`secrets.write` there) could keep a dynamic-secret credential alive past its
intended TTL by renewing it across a clock rollback, or the sweep could
simply fail to revoke an expired one for as long as the rollback persists.
For non-ephemeral backends (the check in `RenewLease` already refuses
renewal outright for cloud-IAM/ephemeral backends), this extends how long a
provisioned backend credential (e.g. a dynamic DB user) stays valid beyond
its promised TTL — a durability/least-privilege erosion, not a disclosure or
authorization-bypass primitive; every other authority check on the lease's
own config/project/environment still applies unchanged.

## Resolution

Tracked as a follow-up `fix(security)` PR, same pattern as
`checkSessionRefreshClockNotRegressed`: a shared in-process watermark
(`dynamicSecretsClockWatermark`) with the same 30s regression tolerance.
`RenewLease` refuses (reusing its existing "lease has expired" error text) when
the clock has regressed past the watermark by more than the tolerance;
`RevokeExpiredLeases` clamps its cutoff to the LATER of the caller-supplied
`before` and the watermark, so a regressed sweep still revokes what it should.
`IssueLease` needs no change (issuing is not a re-check of an existing
expiry). `TestDynamicSecretLeaseRenewal_KnownGap_ClockRollback` is flipped to
assert the fixed behavior in that same PR, and doubles as its red-before/
green-after regression test.

## Ledger

Add a row to `claude/2026-09-15-fuzzing-catches-ledger.md` once the fix PR
lands (coordinator to add per FUZZ-MECH report).

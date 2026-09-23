# FINDING: `cachedImpersonationCeiling` was never vulnerable to a wall-clock step — two proposed fixes would have introduced the bug they set out to close

**Date:** 2026-09-23
**Component:** `internal/core/authz.go` (`cachedImpersonationCeiling`,
`ReauthorizeImpersonation`'s ceiling check, IMP-001/MT-007).
**Status:** **Closed, no bug in `main`.** Two independent proposed fixes
(#1994, #1995) were both closed unmerged after review — each would have
introduced a real regression. Invariant pinned by
`internal/core/impersonation_ceiling_monotonic_test.go` and a doc comment on
`cachedImpersonationCeiling` itself.
**Severity: N/A** — no defect exists in `main` today.

## Background

The #1983 clock-jump investigation flagged `cachedImpersonationCeiling` (a
60-second in-process TTL cache backing `ReauthorizeImpersonation`'s ongoing
"is this impersonation still authorized" check) as the one TTL-based cache in
`authz.go` with no monotonic-watermark protection against a backward
host-clock step — every sibling mechanism in this codebase
(`authEffectiveNow`, `shareEffectiveNow`) has one. Two separate sessions
independently proposed the same fix shape: route the cache's `c.now()` calls
through a new watermarked `impersonationCeilingEffectiveNow`/equivalent,
modeled directly on `authEffectiveNow`.

Both PRs passed their own tests. Review of #1994 found the actual defect.

## Why the original code was already correct

`cachedImpersonationCeiling`'s write and read are **both in-process**:

```go
if entry := v.(ceilingCacheEntry); c.now().Before(entry.expiresAt) {
    return entry.err
}
...
c.impersonationCeilingCache.Store(key, ceilingCacheEntry{err: err, expiresAt: c.now().Add(ceilingCacheTTL)})
```

In production, `c.now` defaults to `time.Now`. Every `time.Time` value
`time.Now()` returns carries a **monotonic clock reading** in addition to its
wall-clock reading (documented Go behavior, `time` package). `Add`,
`Before`, `After`, and `Sub` all use the monotonic reading exclusively when
**both** operands carry one — and the monotonic clock is sourced
independently of the wall clock (`CLOCK_MONOTONIC` or equivalent), so it is
**structurally immune** to a host wall-clock step: an operator's `date -s`,
an NTP correction, or any other wall-clock adjustment never touches it. Both
`entry.expiresAt` and every later `c.now()` reading in this cache's lifetime
carry monotonic readings throughout — so this comparison was already immune
to the exact threat class #1983 investigates, via Go's own language
guarantee, before any of this investigation's changes.

## What #1994 and #1995 each got wrong

Both wired the comparison through a `.UTC()`-calling wrapper
(`authEffectiveNow`-shaped): `now := c.now().UTC()`, then clamp to a
watermark if `now` is before the watermark, else advance the watermark to
`now`. **`.UTC()` unconditionally strips the monotonic reading** — it is not
optional or conditional on whether a step actually occurred.

Once stripped, the SAME backward wall-clock step this cache already
tolerated instead **defeats** the fix: the watermark clamp holds "now" frozen
at the pre-step wall-clock reading for as long as the step lasts. A verdict
cached shortly before a 1-hour backward step is then trusted for
approximately 1 hour instead of the intended 60 seconds — a strictly *worse*
outcome than the code both PRs were trying to fix, and the exact MT-007
exposure window this cache exists to bound, widened rather than closed.

Both PRs' own tests passed anyway, because each used a synthetic fixed
`time.Time` (e.g. `time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)`) as the
injected clock. A `time.Date`-constructed value **never carries a monotonic
reading in the first place** — there is nothing for `.UTC()` to strip that
the test's own fixture hadn't already omitted, so neither test could ever
have detected the regression it shipped alongside, regardless of which
implementation (bare `c.now()` or the `.UTC()`-wrapped version) was under
test.

## Why `authEffectiveNow`/`shareEffectiveNow`'s pattern doesn't transfer here

Those two watermarks are correct for what they actually guard: a comparison
against a **persisted** instant — a DB `ExpiresAt` column, a JWT `exp`/`iat`
claim — that was serialized and deserialized (or parsed from a wire format)
and so **never had a monotonic reading to begin with**. For that comparison,
wall-clock-only is the only option available, and the watermark is the
correct, load-bearing defense against a backward step.

`cachedImpersonationCeiling` compares two **in-process-only** readings that
both still carry monotonic protection. Applying the same watermark pattern
here doesn't add a defense — it **discards a stronger guarantee already in
place** (monotonic immunity) and replaces it with a strictly weaker one
(wall-clock-only, watermark-clamped), which is precisely backward for this
call site.

## Resolution

No production logic change. `cachedImpersonationCeiling` keeps its original
bare `c.now()` on both the read and write side. Added:

1. A doc comment directly above the function explaining the monotonic
   invariant it depends on, and explicitly naming `authEffectiveNow`/
   `shareEffectiveNow`/any new watermark wrapper as the wrong tool here —
   pointing at this finding and the two closed PRs by number, so a future
   editor sees the reasoning before reintroducing the same regression a
   third time.
2. `internal/core/impersonation_ceiling_monotonic_test.go`:
   - `TestCachedImpersonationCeiling_RealClockRetainsMonotonicReading` — the
     direct mechanism check. With the real clock wired in, asserts
     `entry.expiresAt.String()` contains `"m=+"` (the monotonic-reading
     marker Go's `time.Time.String()` documents). Red-proofed: swapping
     `c.now()` for `c.authEffectiveNow()` inside `cachedImpersonationCeiling`
     (reproducing the #1994/#1995 shape) makes this assertion fail
     immediately, with no timing or scheduling involved — restored after
     confirming.
   - `TestCachedImpersonationCeiling_TTLExpiryUsesGenuineElapsedTime` — the
     behavioral companion: caches an ALLOW, advances 61 seconds of
     genuinely monotonic-linked time via `Add()` on a real `time.Now()`
     reading (Go provides no public API to fabricate a `time.Time` whose
     wall and monotonic components diverge — by design, since a forgeable
     monotonic reading would defeat its own purpose — so this is the
     closest faithful reproduction of "genuine elapsed process time"
     achievable without an actual 61-second sleep in the suite), revokes
     the underlying permission, and confirms the next call rechecks and
     denies. This test does NOT discriminate bare `c.now()` from the
     `.UTC()`-wrapped alternative on its own (confirmed: it stays green
     under the red-proof swap above too, since `Add()` shifts wall and
     monotonic by the same delta from a shared base, so there is no
     wall/monotonic divergence for it to expose) — it exists to pin
     ordinary TTL-expiry correctness under real elapsed time, not as the
     regression guard; `TestCachedImpersonationCeiling_RealClockRetainsMonotonicReading`
     is the test that plays that role.

## Open PRs referenced

- #1994 (closed, unmerged): this session's own first attempt.
- #1995 (closed, unmerged): a second, independent attempt with the same
  underlying flaw, found during the same review pass.

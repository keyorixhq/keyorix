# FINDING: HTTP auth-cache session-revocation race lets a deleted session keep authenticating

**Date:** 2026-09-20
**Component:** `server/middleware/auth.go` (`serveAuthCacheHit`), `internal/core/auth.go`
(`SessionLiveForToken`), every "list session hashes → delete → invalidate" call site
enumerated below.
**Status:** **Fixed**, same PR. Proving tests: `TestSessionRevoke_ConcurrentRevokeDoesNotResurrectCachedAuth`,
`TestSessionRevoke_SecondReplicaNeverInvalidatedCacheHitDenied`,
`TestSessionRevoke_RotatedTokenCacheHitDenied` (`server/http/session_revoke_race_test.go`),
`TestSessionCacheChokepoint_CoversEveryVulnerableCallSite` (`server/http/session_cache_chokepoint_test.go`),
and `FuzzConcurrentOpsLinearizable` (`server/http/concurrent_linearizable_fuzz_test.go`,
landed in this PR with 13 archived crashers as seed corpus).
**Severity: Medium.** See "Severity" below.

## Summary

`FuzzConcurrentOpsLinearizable` (a porcupine-checked, true-concurrent stateful
fuzzer) found a linearizability violation on the session-revocation register: a
read that STARTS after a `RevokeUserSessions` call RETURNS can still
authenticate. Confirmed by direct code reading and reproduced deterministically
(not just via the fuzzer's ~1-6%-per-replay stochastic hit rate) — this is a
real product bug, not an oracle bug.

**Root cause:** `RevokeUserSessions` (`internal/core/account_sessions.go`) —
and, it turns out, every other call site with the same "list session hashes,
then DELETE, then invalidate the HTTP auth cache" shape — DELETEs the session
row and only afterward calls `invalidateTokenCache`. Between the DELETE
committing and the invalidate call actually running (a Go-scheduling window,
not a database isolation gap), the HTTP auth cache
(`server/middleware/auth.go`) can still hold a POSITIVE entry for the deleted
session. `serveAuthCacheHit`'s session branch previously re-checked only
`AccountStillUsable` (the owning ACCOUNT's active/blocked state) on every cache
hit — never whether the SESSION ROW ITSELF still existed. A revoke that
deliberately leaves the account active (which is the whole point of
`RevokeUserSessions`, `ChangePassword`, MFA/WebAuthn enrollment changes, etc.)
had no other live-state check to catch this.

## Reproduction

Two independent revokes racing (the fuzzer's own shape): revoke A lists `[T]`
and commits its DELETE, then is descheduled before calling
`invalidateTokenCache`. Revoke B, running concurrently, lists `[]` (A's DELETE
already committed), deletes nothing, invalidates nothing, and returns cleanly.
The positive auth-cache entry for `T`, written by an earlier authenticated
read, is untouched by either revoke at this point — B's invalidate was a
no-op, and A's hasn't run yet. Any request presenting `T` in this window
authenticates.

**Deterministic proof** (not reliant on scheduling luck):
`TestSessionRevoke_ConcurrentRevokeDoesNotResurrectCachedAuth` uses a new,
nil-in-production test-only hook,
`core.SetTestRevokeUserSessionsPreInvalidateHook` (installed by
`internal/core/account_sessions.go`, invoked by `RevokeUserSessions`
immediately after its DELETE commits and immediately before
`invalidateTokenCache` runs), to force revoke A to pause in exactly that
window while revoke B runs to completion. 10/10 runs under `-race` failed on
unfixed code; 10/10 pass with the fix; 10/10 fail again with the fix reverted
(red-proof).

**Fuzzer crasher replay** (`-race`, `GOMAXPROCS=2`, `-count=50` per crasher,
isolated runs): 5 of the 13 archived crashers reproduced the identical
`NOT LINEARIZABLE: register "[sqlite] session revuser"` failure within this
batch (`184007d2d84e3daa`, `57277b609abee46c`, `9259b0e22f7e5be8` at 1/50 each;
`050d80f48e9e77ba` and `e67e1baaaebcd228` reproduced in an earlier combined
run but 0/50 in isolation) — consistent with a genuinely low, stochastic
per-replay hit rate (~1-6%), not a flaky harness. The other 8 crashers showed
0/50 in this batch, consistent with the same low base rate rather than a
different bug. After the fix, all 13 crashers pass in the same replay
configuration.

## Why PostgreSQL never failed in the original soak

The race is entirely **after** both revokes' DB transactions have already
committed — it lives in Go goroutine scheduling between
`DeleteSessionsForUserExcept` returning and `invalidateTokenCache` running, not
in any database isolation semantics. SQLite (running under WAL +
`_busy_timeout=10000` with real per-transaction lock contention on a loaded
box) plausibly widens that scheduling window relative to PostgreSQL's faster,
more uniform round trips. Combined with the low ~1-2% base rate, a
bounded-duration PostgreSQL soak completing with zero hits is consistent with
a probability difference, not a correctness difference between backends.

## Fix

`serveAuthCacheHit`'s session branch now also calls
`core.SessionLiveForToken(ctx, sessionID, token)` — a new core method
(`internal/core/auth.go`) — on every cache hit, alongside the existing
`AccountStillUsable` check. It:

1. Looks up the session by its row id (`GetSessionByID`).
2. Compares the row's own stored `session_token` hash against the PRESENTED
   token's hash — not just the id. Session rotation
   (`RefreshSession`/`RotateSession`, #211) creates a NEW row with a NEW hash
   and marks the OLD row's `RotatedAt`; it never rewrites `session_token` in
   place, so a rotated-out old token's own id already fails the `RotatedAt`
   check below without the hash comparison — but the hash comparison is what
   makes the check safe against ANY session id that doesn't actually belong to
   the presented token (a wiring bug, not rotation), not just that one case.
3. Checks `RotatedAt`, `ExpiresAt`, `AbsoluteExpiresAt` — the same liveness
   checks `SessionStillLive` (the pre-existing gRPC-stream-reauth sibling,
   `internal/core/auth.go:619`) already applies.

Return-value contract matches the PAT/machine branches' existing philosophy: a
DEFINITIVE "not live" (row hard-deleted — `storage.ErrSessionNotFound`/
`storage.IsSessionNotFound`, new sentinel added this PR — hash mismatch,
rotated, or expired) denies and evicts via `denyRevokedCacheHit`; an
INDETERMINATE result (a transient storage error, or `storage.type: remote`,
which has no `GetSessionByID` implementation and returns
`ErrRemoteUnsupported`) falls back to the cached snapshot rather than
fail-closing every session holder on a blip.

`UserContext.SessionID` (new field, both HTTP's `server/middleware/auth.go`
and — pre-existing — gRPC's `server/grpc/interceptors/auth.go`) is populated
on the slow path only, mirroring the gRPC interceptor's own established `#G18`
pattern: after `validateToken` succeeds, `coreService.Storage().GetSession(ctx,
token)` resolves the presented token's own row id. For an impersonation
token this naturally resolves to the impersonation session's own row (`GetSession`
looks up whatever row the PRESENTED token hashes to) — no separate case
needed. Degrades to `nil` (not a request failure) on a lookup error; a `nil`
`SessionID` on a later cache hit skips the new check entirely (exactly pre-fix
behavior for that one entry — a rolling-deploy transition case, not a new
failure mode).

### Call sites covered (single chokepoint, not a per-site patch)

Enumerated every "list session hashes, then DELETE, then invalidate" shape in
`internal/core`. Two classes:

**Vulnerable before this fix** (session-only revocation, no compensating
account-state flip an account-level check could have caught instead) — all 7
covered by `TestSessionCacheChokepoint_CoversEveryVulnerableCallSite`:

- `RevokeUserSessions` (`internal/core/account_sessions.go:38`)
- `DeleteSessionsForUserExcept` (`internal/core/users.go:741`, the `/system`
  proxy's admin session-termination entry point)
- `ChangePassword` (`internal/core/account.go:74`)
- `ActivateMFA` (`internal/core/mfa.go:88`) / `DisableMFA` (`mfa.go:143`)
- `FinishWebAuthnRegistration`'s first-enrollment purge / `DeleteWebAuthnCredential`'s
  last-passkey purge (`internal/core/webauthn.go:151`, `:225`)
- The setup-token-consume MFA-required branch and the auto-login branch
  (`internal/core/setup_consume.go:72`, both paths)

**Already mitigated** (the account-state flip — `IsActive`/`AccountState` —
commits in the SAME transaction as, or strictly before, the session DELETE, so
the pre-existing `AccountStillUsable` check already caught a stale hit
regardless of this bug): `UpdateUser`'s deactivating branch, `DeleteUser`,
`setAccountState`/suspend-reactivate, SCIM `UpdateUser` deactivation, SCIM
`DeleteUser`/deprovision, `RevokeUserCredentialsForDeactivation` (its sole
caller commits the deactivation write first).

The fix is a single chokepoint (`SessionLiveForToken`, wired once into
`serveAuthCacheHit`) rather than a per-site patch — it closes all 7 vulnerable
sites simultaneously, and any future one with the same shape, without touching
any of them.

## Multi-replica finding (and a positive side effect of the fix)

**The HTTP token cache is 100% process-local with no cross-node
invalidation** — confirmed by exhaustive grep: `tokenCache` is a plain
in-process `map[string]tokenCacheEntry{}` guarded by a `sync.Mutex`
(`server/middleware/auth.go:179-180`); `InvalidateTokenCacheByHash`
(`auth.go:1482-1491`) only ever writes into that same local map;
`server/main.go:463` wires it as a bare function pointer with no distributed
backing. This is a KNOWN, DOCUMENTED, ACCEPTED tradeoff —
`docs/adr-039-ha-deployment.md` ("Consequences & caveats"): "the 30-second
token/session caches... are process-local but short-lived and stale-tolerant —
eventual consistency within the TTL is fine for session tokens (which are
revocable and DB-authoritative)."

**This fix improves on that documented bound for the ADR-039 topology
(multiple replicas sharing one HA PostgreSQL).** `TestSessionRevoke_SecondReplicaNeverInvalidatedCacheHitDenied`
proves it directly: two `*core.KeyorixCore` instances share one DB (standing
in for two replicas sharing one PostgreSQL primary) but only one has the cache
invalidator wired (standing in for a replica that never heard about a
sibling's revoke). Before the fix, the never-notified replica's cache hit
still authenticates the revoked token — matching ADR-039's accepted "up to
30s" bound exactly. After the fix, the very NEXT cache hit on that replica
denies it, because `SessionLiveForToken` re-reads the session row from the
SAME shared PostgreSQL database every other replica already writes to — it
doesn't need the eviction notice at all. This is a genuine improvement (next
request, not next-30-seconds) for the documented HA topology, not a new
capability being claimed beyond it.

**This does NOT extend to `storage.type: remote` deployments.**
`RemoteStorage.GetSessionByID` (`internal/storage/store/remote_auth.go:100`)
is unconditionally `remoteUnsupported` — there is no HTTP endpoint backing it.
`SessionLiveForToken` treats that as an indeterminate lookup failure (falls
back to the cached snapshot, per the fix's own fail-open-on-uncertainty
contract) — meaning a `storage.type: remote` deployment's session cache-hit
path is exactly as it was before this fix: unprotected by this specific check,
still bounded only by the documented 30s TTL. Flagging as a residual gap, not
fixing here — `GetSessionByID` has no remote-proxy implementation to fix
without adding a new upstream endpoint, which is out of scope for this PR.

## Stale-field sweep (`UserContext`, report only — not fixed here)

Every field the HTTP `UserContext` fills on the slow path and serves from the
cache on a hit, and whether a cache hit re-checks it after this fix:

| Field | Re-checked on cache hit? |
|---|---|
| `UserID`, `ActorType`, `MachineIdentityID`, `MachineIdentityType` | Identity anchors, not live state; not applicable |
| `SessionAuth` | Fixed for the token's lifetime; not applicable |
| `PATRestriction` | Yes — `CurrentPATRestriction`, pre-existing (#146) |
| `MachineTokenRestriction` | Yes — `CurrentMachineTokenRestriction`, pre-existing (#G18) |
| **Session row liveness (id+hash / rotated / deleted / expired)** | **Yes — `SessionLiveForToken`, THIS fix** |
| Owning account active/blocked | Yes — `AccountStillUsable`, pre-existing (#G18) |
| `Username`, `Email` | **No.** A rename/email-change mid-window serves the stale value for up to `validTokenTTL` (or the full ADR-039 cross-replica window). Cosmetic in most call paths (audit attribution uses the DB row, not the cached context), but not verified exhaustively here. |
| `Roles` | **No.** A role grant/revoke mid-window is not reflected on a cache hit — pre-existing, unrelated to this fix's mechanism (authorization decisions re-resolve permissions per request via `core.Authorize` against current DB state per its own doc comment, not from this cached list, which narrows but does not eliminate the exposure — not verified exhaustively here). |
| `AccountState`, `Restricted` | **Partially.** `AccountStillUsable` denies outright once the account is `AccountLoginBlocked` (suspended/deprovisioned), but `AccountRestricted` is `true` for `AccountPendingFirstLogin`/`AccountPasswordResetRequired` — states `AccountLoginBlocked` does NOT cover. A transition into either of those states mid-window is invisible to `AccountStillUsable`, so `EnforceAccountRestriction` (`server/middleware/auth.go:769`, which reads `userCtx.Restricted` directly) keeps enforcing the STALE (unrestricted) value on a cache hit until the entry naturally expires. Confirmed via code reading, not independently fixed or tested in this PR — a distinct gap from the one this PR closes. |
| `MFAEnabled` | **No, directly** — but every path that flips it (`ActivateMFA`/`DisableMFA`) also unconditionally purges ALL of that user's sessions via the same shared helper this fix protects, so in practice every session that could have observed a stale `MFAEnabled` is denied outright by `SessionLiveForToken` on its next hit, not merely serving a stale flag. No known path flips `MFAEnabled`/`WebAuthnEnabled` without also purging sessions. |

The `Username`/`Email`/`Roles`/`AccountState`-restriction gaps are pre-existing,
independent of this fix's mechanism, and out of scope for this PR — recorded
here for visibility per this repo's "what does a mechanism silently skip, and
does it say so" standard, not being fixed here.

## Severity

- **Who can trigger it:** Only an actor who already holds authority to revoke
  a user's own sessions (an admin with `users.write`, or the user themself via
  a password change / MFA change) — this is not an unauthenticated or
  cross-tenant escalation. The exposure is that the admin's OWN revoke action
  doesn't take effect as fast as intended, momentarily.
- **Window:** A Go-scheduling race between a DELETE commit and the following
  statement — milliseconds, and only under a SPECIFIC concurrent-revoke
  interleaving (two revokes of the same user's sessions racing each other).
  Empirically ~1-2% per fuzzer replay when the exact interleaving isn't
  forced.
- **Preconditions:** Two concurrent revoke-shaped operations against the SAME
  user (revoke sessions + change password racing each other; two admin revoke
  clicks; a revoke racing the user's own MFA change), or — separately, with a
  MUCH larger and non-probabilistic window — a `storage.type: local`-over-shared-PostgreSQL
  multi-replica deployment, where the ADR-039-documented (and now,
  post-fix, improved) 30-second cross-replica bound applies.
- Rated **Medium**, not Low: the security-relevant consequence — a
  just-revoked session token continuing to authenticate — is exactly the kind
  of "incident response didn't actually take effect" gap this repo's own
  `RevokeUserSessions` doc comment calls out as the whole point of the
  feature ("use this when a user's sessions may be compromised... the
  incident-response control"), even though the trigger conditions are narrow
  and require existing revoke authority.

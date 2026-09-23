# FINDING: break-glass revoke's role removal and activation-state update were two independent storage calls, not one transaction

**Date:** 2026-09-23
**Component:** `internal/core/break_glass.go` (`RevokeBreakGlass`, new
`RevokeBreakGlassActivationAtomic`); `server/http/handlers/break_glass_proxy.go`
(`RevokeBreakGlassActivationProxy`).
**Status:** Fixed, same PR as this finding doc.
**Severity:** High — a genuine mid-revoke storage failure could leave an
emergency role grant LIVE in `user_roles` while every other surface (API
response semantics, the activation record, the audit trail) reported the
grant revoked. Classified as **security (privilege retained)**, with a
compounding **integrity/audit** defect (the compliance record for the
revocation itself never gets written either). See "Severity" below.

Found by `FuzzStorageFaultOperations` (`server/faultops`) — corpus entry
`7c0a2492ee5d1dfa`, `fault=(RemoveRole, NthCall=1, kind=effect-then-error)` on
`REST POST /api/v1/system/break-glass/{id}/revoke`.

## Summary

Both break-glass revoke code paths performed the same two mutations as
independent, unrelated top-level storage calls:

1. Remove the emergency role grant (`RemoveUserRole` / `RemoveRole`).
2. Mark the activation record `revoked` (`RevokeBreakGlassActivation`).

A genuine failure in step 1 was already handled as an abort (a `#303` fix
predates this one — see `break_glass_revoke_test.go`'s existing tests). What
neither path handled is a storage fault where step 1's own effect (the
`DELETE`) actually lands but the call still reports failure — an
"effect-then-error" fault, exactly the shape a connection drop immediately
after a successful write produces. The caller then correctly treats the
*reported* error as a hard abort and never reaches step 2 — but the role
grant is already gone. Result: role removed, activation still `"active"`,
no `break_glass.revoked` audit event. Every surface downstream of this
(the API response, `ListBreakGlassActivations`, the audit trail) reports the
activation as still live, while the actual privilege has already been
withdrawn — the reverse-looking but equally real half of the same defect
also holds: nothing here prevented the opposite skew (state marked revoked
while the role survives) had the fault landed on the *second* call instead.

## Reachability

Two independent entry points share the exact shape, both reachable today:

- **`internal/core.RevokeBreakGlass`** — backs the human-facing REST route
  (`POST /api/v1/projects/{id}/break-glass/{activationId}/revoke`,
  `server/http/handlers/break_glass.go`) and the gRPC
  `BreakGlassService.RevokeBreakGlass` RPC
  (`server/grpc/services/break_glass_service.go`). Both transports call this
  one core function with no independent logic of their own.
- **`server/http/handlers.RevokeBreakGlassActivationProxy`** — the `/system`
  raw-storage-primitive proxy a downstream `storage.type: remote` server's
  break-glass revoke traffic is proxied through (ADR-049). Scheduled for
  deletion under **ADR-108 Phase 6** (the CLI/server split), but live and
  reachable today, gated on `system.write` plus a re-derived
  `roles.assign`-at-project-scope check (`RequireRolesAssignAuthority`) —
  see that handler's own extensive doc comment for the (unrelated, already
  fixed) history of authority bugs on this exact route.

A third possible entry point — an expiry sweeper that revokes on TTL lapse —
**does not exist**: `ListBreakGlassActivations`'s doc comment
(`internal/core/break_glass.go`) documents that TTL lapse is a pure read-time
projection (`State` computed at read time, never persisted from a sweep), and
the only place a TTL-lapsed row is ever reconciled to a real state transition
is `ReconcileExpiredBreakGlassActivation`, called from `ActivateBreakGlass`
(a *new* activation's own path, not a revoke). So exactly two entry points
needed the fix, not three.

## Reproduction (fuzzer trace)

```
op="REST POST /api/v1/system/break-glass/{id}/revoke"
fault=(RemoveRole, NthCall=1, kind=effect-then-error)
ORACLE (d) VIOLATION — effect-then-error state matches NEITHER the pre-fault
state nor the fault-free reference state. Differing tables vs before:
[UserRole]; vs reference: [BreakGlassActivation AuditEvent]
```

Minimized input: `server/faultops/testdata/fuzz/FuzzStorageFaultOperations/7c0a2492ee5d1dfa`.
Replayed against pre-fix code (`go test ./server/faultops -run
'FuzzStorageFaultOperations/7c0a2492ee5d1dfa' -v`): confirmed red (verified by
temporarily reverting the fix in this worktree and re-running — see PR).
Against the fixed code: confirmed green.

## Severity

- **Security (privilege retained), not merely cosmetic**: the whole point of
  break-glass is that the grant is *time-bound*; an early, deliberate revoke
  exists precisely for "the incident is over, or was a mistake, end it now."
  A half-commit that reports success/removed-looking state while the grant
  survives defeats that early-termination guarantee at the exact moment an
  operator is relying on it — likely during or immediately after a live
  incident.
- **Does a later sweep re-grant or skip it?** No re-grant risk:
  `ActivateBreakGlass` refuses a *new* activation while an existing row for
  the same `(project, user)` reads `State == active` — including the
  post-fault, half-committed row here, since its `State` was never updated
  — so the user cannot double-dip a second grant on top of the leaked one.
  But this is a coincidental side effect of an unrelated guard, not something
  this defect's design relied on, and it does nothing to close the actual
  gap (the leaked role stays live until someone manually notices and revokes
  it again).
- **Does it look active in the UI/API?** Yes — `GetBreakGlassActivation`/
  `ListBreakGlassActivations` both read the persisted `State` column
  (projected only for TTL lapse, not for this kind of storage-fault skew), so
  every surface reports `"active"` while the role is already gone. An
  operator re-attempting the revoke gets a normal "revoke succeeded" the
  second time (RemoveRole's own `ErrRoleNotAssigned`-tolerant path handles
  the now-actually-missing grant), which self-heals the state — but only if
  someone notices the first attempt reported success while nothing visibly
  changed, and retries.
- **Missing audit is a distinct, compounding compliance issue**: break-glass
  activation is explicitly built for NIS2/DORA incident-response record
  keeping (`break_glass.go`'s own package doc: "recorded as a queryable
  BreakGlassActivation for post-hoc review"). A revoke with no
  `break_glass.revoked` audit event is a hole in exactly the record an
  auditor or incident responder would rely on afterward — independent of
  whether the underlying privilege change itself was also inconsistent.

## Fix

`internal/core/break_glass.go`: new exported
`RevokeBreakGlassActivationAtomic(ctx, actorID, actorMachineID, activation,
now)`, called by both `RevokeBreakGlass` and (via `h.coreService`)
`RevokeBreakGlassActivationProxy` — one function, not two independently
maintained copies of the same sequence. It:

1. Runs the same last-project-admin guard `RemoveUserRole`'s project-scope
   branch already applies (`WithNamedLock` + `guardLastProjectAdmin`), kept
   **outside** the transaction below, for the same lock-ordering reason that
   code's own doc comment gives (a named lock must never be held while a
   separate storage transaction is also open). A break-glass emergency role
   can never carry `roles.assign` at *activation* time
   (`ActivateBreakGlass`'s own policy check) — but a role's permission set
   can be edited afterward, so this still runs a real check rather than
   assuming it can never fire.
2. Opens **one** `storage.WithTransaction`: `tx.RemoveRole` (tolerating
   `ErrRoleNotAssigned` — the grant already auto-expired or a racing revoke
   already removed it) then `tx.RevokeBreakGlassActivation`, the same
   conditional `WHERE state IN (active, expired)` update as before. A fault
   anywhere in this block — including an effect-then-error fault exactly
   like the one that found this bug — now rolls back **both** statements
   together: either the role is gone AND the activation is revoked, or
   neither happened. This is what closes the half-commit.
3. Audits and evicts the session cache strictly **after** commit — the same
   convention `CreateRole`/`UpdateRole` already use (`rbac_roles.go`, #1969
   class / PR #1996): an event recorded before the transaction resolves
   could survive a later rollback and assert an effect that never landed.

`server/http/handlers/break_glass_proxy.go`: `RevokeBreakGlassActivationProxy`
now calls the same `RevokeBreakGlassActivationAtomic` instead of its own
inline `RemoveUserRole` + `RevokeBreakGlassActivation` + `LogBreakGlassRevoked`
sequence — the exact duplication that let this drift in the first place (see
that file's own doc comment on the *previous* fix to this same handler, #1542
era, which already fixed a different variant of "these two effects aren't
actually linked").

### No SAVEPOINT needed, unlike the `#1996`/create-ops precedent

The task's own template (`CreateRole`/`UpdateRole`, PR #1996) needed a nested
`tx.WithTransaction` (SAVEPOINT) around its "intentionally non-fatal" steps,
because those steps can hit a **genuine PostgreSQL constraint violation** —
and per this repo's own standing rule, catching a constraint violation after
the failing statement does not un-poison the transaction; only a SAVEPOINT
does. This fix's own "non-fatal" step — `RemoveRole` returning
`ErrRoleNotAssigned` — is a different shape: `local_rbac.go`'s `RemoveRole`
derives that sentinel from `result.RowsAffected == 0`, i.e. a `DELETE` that
matched zero rows. That is **not a failing SQL statement** at the Postgres
protocol level at all — it is a successful statement with an empty result,
turned into a Go-level error only after the fact. There is nothing for a
SAVEPOINT to contain. This is verified against real Postgres, not just
asserted: see `TestRevokeBreakGlassActivationAtomic_PostgresTransaction_AlreadyGoneRoleRemovalCommits`
below, which forces the exact zero-rows condition and confirms the
surrounding transaction commits normally with no savepoint involved.

### Remote-storage note

`RemoteStorage.WithTransaction` is a documented no-op
(`internal/storage/store/remote_transaction.go`): it just calls `fn(rs)`
directly with no real transaction. This fix's atomicity guarantee only holds
for a `LocalStorage`-backed caller.
`RevokeBreakGlassActivationProxy` is unaffected by this caveat — it always
runs against `LocalStorage` (`validateRemoteStorageNotServer` forbids wiring
`RemoteStorage` into `server/http/handlers` at all). `RevokeBreakGlass`'s own
role-removal step is independently broken under `storage.type: remote`
already, for an unrelated reason: `RemoveUserRole`'s project-scoped
`RemoveRole` call has no registered wire route (`#1511`, documented in
`RevokeBreakGlassActivationProxy`'s own pre-existing doc comment). This fix
does not worsen that pre-existing gap and does not close it either — `#1511`
is tracked separately.

## The `/system` proxy tier and ADR-108 Phase 6

`RevokeBreakGlassActivationProxy` is explicitly scheduled for deletion under
ADR-108 Phase 6 (the CLI/server split). It is fixed here anyway because it is
reachable today and shares the exact defect shape. What survives the split:
the shared `RevokeBreakGlassActivationAtomic` in `internal/core` — the
transactional core the human REST route and the gRPC route both already
depend on independent of the proxy's fate. What does not survive: the proxy
handler itself and its wire-shape plumbing (`breakGlassRevokeProxyRequest`,
`breakGlassActivationProxyWire`, `breakGlassNotActiveCode`) — deleting it
later removes one of the two call sites, not the fix.

## Second defect found during the fix's own fuzz-validation burst

The 10-minute `-fuzz '^FuzzStorageFaultOperations$'` validation run (see
`docs/g80-remediation-notes.md`'s established practice: this repo's
`createuser-best-effort-panic-002`/`-003` closures were found the identical
way) surfaced a second, closely related defect on the same route before
settling into a clean run:

```
input=2e7d403231 -> op="REST POST /api/v1/system/break-glass/{id}/revoke"
fault=(method=ListSessionTokenHashesForUser, NthCall=1, kind=panic)
ORACLE (a) VIOLATION — reported an ERROR but logical state changed anyway
(partial commit). Differing tables: [UserRole AuditEvent BreakGlassActivation]
```

`RevokeBreakGlassActivationAtomic`'s post-commit `evictUserSessionCache` call
(`internal/core/account.go`) had no panic protection. A panic there — after
the transaction had already committed the role removal and activation-revoke
— propagated up, skipped the `LogBreakGlassRevoked` audit call that follows
it, and surfaced to the HTTP layer as a request failure, even though the
underlying state had already fully and correctly changed. Same "best-effort
helper masks an already-successful primary operation" shape `emitAudit`
(`service.go`) was already hardened against; `evictUserSessionCache` itself
was not, and it is a single choke point shared by two OTHER call sites too
(`rbac_management.go`'s `RemoveUserRole`, both the global-admin and
project-scope removal branches) — all three now covered by one fix, not a
patch at the one site the fuzzer happened to reach it through. Fixed by
adding the identical `defer recover()` + `SECURITY`-prefixed log line
`emitAudit` already uses, directly in `evictUserSessionCache`.

Regression seed: `server/faultops/testdata/fuzz/FuzzStorageFaultOperations/c3012b444731c557`
(committed). Confirmed red against the pre-fix `evictUserSessionCache` (no
`recover`), green after.

## Out-of-scope observation, not fixed here

The same validation burst separately surfaced an apparently pre-existing,
unrelated defect on `POST /api/v1/users/` (`CreateUser`'s baseline
`system_viewer` role auto-assignment, `internal/core/users.go`) — a
`GetRoleByName` fault reported via `ORACLE (a) VIOLATION`, `Differing tables:
[UserRole]`. This code path has nothing to do with break-glass and was not
touched by this PR. It may not even be a genuine bug rather than a
fuzz-oracle classification gap (the role assignment is INTENTIONALLY
non-fatal and already SAVEPOINT-protected and panic-guarded per its own
extensive doc comment — the "differing tables" the oracle flags may be the
documented, by-design "user created without its baseline role" outcome, not
an accidental partial commit; distinguishing the two needs someone who owns
that code path, not a guess made in passing here). The minimized seed
(`a506a678b50514c8`) was deliberately **not committed** to this PR — landing
a permanently-failing corpus entry for a bug this PR does not fix would block
every future `-fuzz` run of this target for everyone, seed-replay-first,
until someone else's PR addresses it. Flagging for separate triage rather
than silently leaving it for the next unrelated campaign to rediscover.

## Tests

- `server/faultops/testdata/fuzz/FuzzStorageFaultOperations/7c0a2492ee5d1dfa`
  (fuzzer-found regression seed, committed; red before, green after — see
  "Red-proof").
- `server/faultops/testdata/fuzz/FuzzStorageFaultOperations/c3012b444731c557`
  (fuzzer-found regression seed for the `evictUserSessionCache` panic defect
  above, committed; red before, green after).
- `internal/core/break_glass_revoke_test.go` (pre-existing, unchanged):
  `TestRevokeBreakGlass_GenuineRoleRemovalFailureAbortsRevoke` and
  `TestRevokeBreakGlass_AlreadyGoneRoleRemovalIsNotAFailure` already cover the
  shared core function's control flow under a mocked `RemoveRole`
  failure/success — both still pass unmodified against the new
  `RevokeBreakGlassActivationAtomic`-based implementation (one behavioral
  adjustment was needed: session-cache eviction now only fires when a role
  was actually removed, matching the pre-fix behavior exactly, rather than
  unconditionally after every commit).
- `internal/core/break_glass_revoke_atomicity_pg_test.go` (new, PG-gated on
  `KEYORIX_TEST_PG_DSN`):
  - `TestRevokeBreakGlassActivationAtomic_PostgresTransaction_GenuineFailureRollsBackBoth`
    — a real BEFORE DELETE trigger forces a genuine aborting Postgres error on
    every `user_roles` delete; confirms the call returns an error, the
    activation is re-read (fresh query) as still `"active"`, the role grant
    still exists, and no `break_glass.revoked` audit event exists. Proves
    "old state or full new state, never a mix."
  - `TestRevokeBreakGlassActivationAtomic_PostgresTransaction_AlreadyGoneRoleRemovalCommits`
    — pre-deletes the role grant directly (the real "already gone" shape),
    confirms the call succeeds, the activation commits as `"revoked"`, the
    audit event exists, and a second call against the now-revoked row
    correctly returns `ErrBreakGlassNotActive`. Proves the tolerated
    zero-rows case does not poison the transaction, with no savepoint.

## Red-proof

Reverting `internal/core/break_glass.go` and
`server/http/handlers/break_glass_proxy.go` to their pre-fix form (verified
via `git stash` in this worktree, not committed) and replaying
`7c0a2492ee5d1dfa` reproduces the original `ORACLE (d) VIOLATION` exactly.
Restoring the fix returns it to green. Full `internal/core`,
`server/faultops`, `server/http/handlers`, `server/http/handlers/contracttest`,
and `server/grpc/services` suites pass with no regressions; `gosec` and
`golangci-lint` report zero issues on the changed packages.

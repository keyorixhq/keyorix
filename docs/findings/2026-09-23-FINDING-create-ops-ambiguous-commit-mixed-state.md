# FINDING: multi-step `Create*` operations leave a mixed (neither old nor new) state when the first storage call's own result is ambiguous

**Date:** 2026-09-23
**Component:** `internal/core/catalog.go` (`CreateProject`, `CreateProjectWithEnvs`);
`internal/core/secrets.go` (`CreateSecret`); `internal/core/users.go` (`CreateUser`);
`internal/core/secrets_versions.go` (`storeSecretVersion`, signature change to
support the `CreateSecret` fix).
**Status:** Fixed, same PR as this finding doc (first-party policy: findings are
fixed and disclosed together).

Found by `FuzzStorageFaultOperations` (`server/faultops`) fuzzing
`CreateProject` — corpus entry `d8a18b028bbc335f` (minimized input `MC722`,
already minimal by construction of Go's fuzz engine: 5 bytes, one per decoded
field). A sibling sweep of every `(c *KeyorixCore) Create*` method in
`internal/core` for the same shape then found two more instances that were
already known but unfixed (`CreateSecret`, `CreateUser` — both previously
catalogued in `multiStepAmbiguousCommitExceptions` as "needs a product
decision, not a small patch") and one more that wasn't yet catalogued at all
(`CreateProjectWithEnvs`, identical shape to `CreateProject`, same file).

## Summary

Each of these operations makes a first storage call whose own result can be
ambiguous under a real-world "effect committed, acknowledgment lost" fault
(`faultstorage.KindEffectThenError` — the fuzz harness's model for exactly
this class): the underlying write actually happens, but the caller is told it
failed. Before this fix, every one of these functions returned immediately on
that error, with no ID to reconcile against and — critically — with a SECOND
storage call still pending that never ran:

```go
// CreateProject, pre-fix
project, err := c.storage.CreateProject(ctx, &models.Project{Name: name, Description: description})
if err != nil {
    return nil, fmt.Errorf("failed to create project: %w", err)
}
for _, envName := range defaultEnvironmentNames {
    c.storage.CreateEnvironment(ctx, &models.Environment{Name: envName, ProjectID: project.ID})
    // never reached when the fault above fires
}
```

Result: the `Project` row is genuinely committed (the fault model's "effect"
is real), but the environment-seeding loop never runs — a state matching
NEITHER the pre-call baseline (nothing exists) NOR the fault-free reference
run's outcome (project + environments both exist). `FuzzStorageFaultOperations`'s
oracle (d) exists specifically to catch this: for an `effect-then-error`
fault, the final state must match old-or-new, never a mix.

`CreateSecret` and `CreateUser` have the identical shape: `CreateSecret`'s
first call is `c.storage.CreateSecret` (the `SecretNode` row), with
`storeSecretVersion` (the version-1 row) pending; `CreateUser`'s first call is
`c.storage.CreateUser` (the `User` row), with the `system_viewer` role grant
pending.

## Reachability

Directly reachable by any authenticated caller with permission to create a
project, secret, or user — `POST /api/v1/projects`, `POST /api/v1/secrets/`,
`POST /api/v1/users/`, and their gRPC/CLI-embedded equivalents. Triggered by
any real-world cause of "the write committed but the response was lost"
(a network partition between the app and DB tier after commit, a request
timeout on the ack, a proxy/load-balancer dropping the response) — not
adversarial input, an ordinary infrastructure hiccup.

## Reproduction (fuzzer trace)

```
op="REST POST /api/v1/projects" fault=(method=CreateProject, NthCall=1, kind=effect-then-error)
ORACLE (d) VIOLATION — effect-then-error state matches NEITHER the pre-fault
state nor the fault-free reference state. Differing tables vs before: [Project];
vs reference: [Environment]
```

Minimized input: `server/faultops/testdata/fuzz/FuzzStorageFaultOperations/d8a18b028bbc335f`
(hex `4d43373232`, i.e. `MC722`). Replayable standalone:
`REPLAY_HEX=4d43373232 go test ./server/faultops/... -run TestReplayStorageFaultInput -v`.

`CreateSecret` (hex `02004d0002`) and `CreateUser` (hex `0600580002`) reproduce
the identical shape — confirmed by replaying both against pre-fix code, where
each produced the `multiStepFirstCallAmbiguousCommit` "FLAG FOR REVIEW" log
line (the mixed-state condition was already firing, just downgraded from a
hard failure by the existing exception-list entries, not absent).

## Impact

A project stuck in this state (row committed, zero environments, caller told
"error") is not dangerous, just confusing: it is fully listable and deletable
through the normal `ListProjects`/`DeleteProject` paths (neither requires an
environment to exist), so an operator who notices it can clean it up. It
cannot be used to create secrets yet, since `CreateSecret` requires an
`EnvironmentID` — the project is inert until someone adds an environment via
`CreateEnvironment`. The retry case that looks dangerous is actually safe: a
client that retries the same create call hits `storage.ErrDuplicateProjectName`
on the name index and gets a clean "a project with this name already exists"
error, not a silent duplicate and not a false success — confusing UX, no data
corruption. The equivalent analysis holds for `CreateSecret`/`CreateUser`: an
orphaned `SecretNode` with no version, or a `User` with no baseline role, is
inert/incomplete but not itself exploitable or corrupting.

## What this is NOT

**Two separable problems, only one of which this fix closes** — worth stating
explicitly since an earlier pass at this finding conflated them:

1. **Mixed state** (this fix): the caller's *own* prior write and a *later*
   step in the same operation can end up half-applied. A transaction closes
   this — an effect-then-error fault fires on a real write made through the
   transaction-scoped storage handle (`faultstorage`'s shared call-count state
   is deliberately consistent across a `WithTransaction` boundary — confirmed
   by reading `faultstorage.go`, not assumed), and if the wrapping function
   then returns that error, `WithTransaction` rolls back what was never
   actually committed. Old-state and new-state are both reachable; a mix
   isn't.
2. **Ambiguous response** (NOT fixed here, tracked separately — see the
   companion ADR outline `docs/adr-draft-request-idempotency-for-create-operations.md`):
   the client is still told "error" even on the lost-ack branch where the
   write in fact committed in full. No idempotency key exists to let a client
   (or this fix) distinguish "my create failed" from "my create succeeded but
   I never heard back." This is a request/API-design gap, not something a
   database transaction can close — deferred to a product decision, not
   defaulted into via this fix.

Not an authz bypass, not a privilege escalation, not a security-boundary
issue — every affected operation already required the same permission it
always did; this only changes what state a fault leaves behind.

## Remote-storage caveat

`storage.WithTransaction`'s own doc comment: the remote backend runs `fn`
directly with no client-side transaction (`RemoteStorage.WithTransaction` is a
no-op passthrough). This does not weaken the fix in practice: `storage.type:
remote` cannot back a server process at all — `validateRemoteStorageNotServer`
(`internal/config/config.go`, ADR-083) unconditionally refuses to boot a
server configured with it, so `storage.type: remote` is CLI-only, and every
server-side path (where these three operations actually run) gets the real,
local transaction.

## Fix

`CreateProject`, `CreateProjectWithEnvs`, `CreateSecret`, and `CreateUser` each
now wrap their ENTIRE multi-step sequence — not just the first call — in one
`storage.WithTransaction`. The already-accepted non-fatal tradeoffs
(`CreateEnvironment` seeding failures, `AssignRole` failures) stay non-fatal:
they're still logged-and-continue inside the transaction, so only a failure of
the FIRST call (the one that was ambiguous) can trigger a rollback.
`storeSecretVersion` gained a `db storage.Storage` parameter so `CreateSecret`
can route its second call through the same transaction-scoped handle; its
other two callers (`UpdateSecret`'s helper path, `RotateSecret`'s retry loop
in `storeNextSecretVersion`) pass `c.storage` unchanged — out of scope for
this fix, not touched.

`CreateSecret`'s old compensating cleanup (`c.storage.DeleteSecret` on a
version-creation failure) is removed — a transaction rollback achieves the
same "as if nothing happened" outcome without a second best-effort delete
that could itself fail and leave the orphan behind anyway.

`multiStepAmbiguousCommitExceptions`'s `CreateSecret`/`CreateUser` entries are
removed in this same PR — the replay evidence below proves both are now
tx-fixed, and `FuzzStorageFaultOperations` is their regression test going
forward. `CreateProject`/`CreateProjectWithEnvs` were never added to that list
(the fix landed before they needed to be).

## Per-(operation, NthCall) validation table

Every relevant `(method, NthCall)` pair across all three sequences, faulted
with `kind=effect-then-error`, replayed against the fixed code:

| Op | Method | NthCall | Result |
|---|---|---|---|
| `POST /api/v1/projects` | `CreateProject` | 1 | PASS |
| `POST /api/v1/projects` | `CreateEnvironment` | 1 | PASS |
| `POST /api/v1/projects` | `CreateEnvironment` | 2 | PASS |
| `POST /api/v1/projects` | `CreateEnvironment` | 3 | PASS |
| `POST /api/v1/secrets/` | `CreateSecret` | 1 | PASS |
| `POST /api/v1/secrets/` | `CreateSecretVersion` | 1 | PASS |
| `POST /api/v1/users/` | `CreateUser` | 1 | PASS |
| `POST /api/v1/users/` | `AssignRole` | 1 | PASS |

Full existing seed/crasher corpus (17 entries, `server/faultops`) also passes
against the fixed code. `internal/core`, `internal/core/storage`, and
`internal/storage/store` (the last needs `-timeout 20m`, a known pre-existing
harness limit unrelated to this fix — confirmed by running it standalone and
green at 864s) all pass with no regressions.

## Red-proof

**Direction 1 (fix removed → red):** reverting `CreateProject` to the
unwrapped, pre-fix form and replaying `d8a18b028bbc335f` reproduces the exact
original failure: `ORACLE (d) VIOLATION ... Differing tables vs before:
[Project]; vs reference: [Environment]`.

**Direction 2 (partial fix is insufficient → red):** wrapping ONLY the first
call is not equivalent to wrapping the whole sequence. Demonstrated on
`CreateSecret` specifically (not `CreateProject`'s environment loop — that
loop's failures are non-fatal by design with no compensating cleanup ever
attached to them, so no fault on it can produce a mixed-state violation either
before or after this fix; the meaningful version of this red-proof needs a
second step whose failure is supposed to be COMPENSATED, which `CreateSecret`'s
version-creation step is): reverting to "wrap only `CreateSecret`, call
`storeSecretVersion` outside any transaction, no compensating cleanup restored"
and faulting `(CreateSecretVersion, NthCall=1, kind=error)` — a genuine,
non-ambiguous failure of the second call — reproduces a mixed-state violation:
`ORACLE (a) VIOLATION — reported an ERROR but logical state changed anyway
(partial commit). Differing tables: [SecretNode]`. This is exactly why the fix
wraps the full sequence rather than only the call the original crasher
happened to target.

**Validation burst:** `FuzzStorageFaultOperations` run with `-race`,
`-parallel=4`, against the fixed code (10-minute budget requested; `go test
-fuzz` stops at the first failing input rather than running the full budget).
619 execs across the full operation catalog — none on `CreateProject`,
`CreateSecret`, or `CreateUser` reproduced any issue — before surfacing a
**separate, pre-existing, unrelated** finding: `(op="REST PUT
/api/v1/secrets/{id}", method=GetLatestSecretVersion, NthCall=1, kind=error)`
→ oracle (a) violation, `Differing tables: [SecretVersion AuditEvent]`
(input `1fefa95ddd2b26bb`). Confirmed unrelated to this fix by code-path
inspection: `UpdateSecret`/`RotateSecret` reach `storeNextSecretVersion`
(`secrets_versions.go`), not `storeSecretVersion` directly — this fix only
added a parameter to `storeSecretVersion` and changed nothing in
`storeNextSecretVersion`'s own retry/error-handling logic, which is where
`GetLatestSecretVersion`'s result is consumed. Not investigated or fixed
here — reported separately, out of scope for this PR.

## Deferred: request idempotency

The ambiguous-response half of this defect (item 2 under "What this is NOT"
above) is intentionally not addressed here. See
`docs/adr-draft-request-idempotency-for-create-operations.md` (unnumbered,
proposed, deferred) for the outline and reopening triggers.

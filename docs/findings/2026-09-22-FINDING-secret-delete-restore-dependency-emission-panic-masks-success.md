# FINDING: a panic inside a "best-effort, primary operation already succeeded" step masks an already-successful request as a failed one

**Date:** 2026-09-22
**Component:** `internal/core/secret_dependencies.go` (`emitDependencyLifecycleEvents`,
called from `secrets.go`'s `DeleteSecret`/`RestoreSecret`); `internal/core/users.go`
(`CreateUser`'s password-history seed + `system_viewer` auto-assign);
`internal/core/service.go` (`emitAudit`, the single choke point every
`c.Log*`/audit-write helper funnels through); `internal/core/catalog.go`
(`CreateProject`/`CreateProjectWithEnvs`'s default/requested-environment seeding).
**Status:** Fixed. First two occurrences landed with this finding doc; a
third live occurrence (`internal/core/catalog.go`, below) was found and
fixed 2026-09-23 in PR #1988 (policy change: first-party findings are fixed
and disclosed together — no customers yet).

Found by two separate unattended final-checks fuzz bursts
(`FuzzStorageFaultOperations`, `server/faultops`), run back-to-back after
coverage batch 6 landed — neither from a hand-written seed. The SAME defect
shape recurred live twice in immediate succession (first on
`DeleteSecret`/`RestoreSecret`, then on `CreateUser`), which is why this doc
now covers three sites instead of one: two found live, one (`emitAudit`)
fixed proactively at the shared choke point once the pattern's second live
occurrence made it clear this was recurring, not a one-off.

## Summary

`DeleteSecret` (`internal/core/secrets.go:474`) deletes the secret row first,
then calls `emitDependencyLifecycleEvents` purely to emit audit events for any
dependency edges the delete invalidates:

```go
func (c *KeyorixCore) DeleteSecret(ctx context.Context, id uint) error {
    ...
    if err := c.storage.DeleteSecret(ctx, id); err != nil {
        return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
    }
    // Emit an audit event for every dependency edge incident to this secret so
    // operators know which rotation plans are affected (best-effort; the delete
    // already succeeded).
    c.emitDependencyLifecycleEvents(ctx, EventSecretDependencyInvalidated, 0, id, secret.ProjectID, secret.Name)
    return nil
}
```

`emitDependencyLifecycleEvents` (`internal/core/secret_dependencies.go:350`,
pre-fix) correctly treated a returned error from its own
`ListSecretDependenciesForProject` call as best-effort — its own doc comment
says so explicitly ("Errors from the edge list query are logged but never
surface to the caller — the delete/restore already succeeded and the audit
emission is best-effort"):

```go
func (c *KeyorixCore) emitDependencyLifecycleEvents(ctx context.Context, eventType string, actorID, secretID, projectID uint, secretName string) {
    edges, err := c.storage.ListSecretDependenciesForProject(ctx, projectID)
    if err != nil {
        return // best-effort; the primary operation already succeeded
    }
    ...
}
```

But it had no protection against a **panic** during that same call — only
against a returned `error`. A panic there propagates straight up through
`emitDependencyLifecycleEvents`, through `DeleteSecret` (which never gets to
its `return nil`), through the HTTP handler, and is caught by the real,
outermost `Recovery` middleware (`server/http/router.go`), which correctly
turns it into an honest-looking `500`. Correctly, in the sense that no panic
escapes the process — but dishonestly, in the sense that `c.storage.DeleteSecret`
had **already committed** several lines earlier. The caller is told the
request failed when the secret was, in fact, already deleted.

`RestoreSecret` (`internal/core/secrets.go:508`) calls the exact same
function, after its own `c.storage.RestoreSecret` has already committed —
identical exposure, same root cause, same fix.

## Reachability

Directly reachable by any authenticated caller with permission to delete or
restore a secret — an ordinary REST call (`DELETE /api/v1/secrets/{id}`,
`POST /api/v1/secrets/{id}/restore`), no `/system` proxy or unusual path
involved. Any transient failure in the dependency-graph read that happens to
panic rather than return an error (a nil-pointer dereference in a driver, an
`index out of range` on a malformed row, a storage-layer bug) triggers it —
no adversarial setup required.

## Reproduction (fuzzer trace)

World: fresh in-memory SQLite, one bootstrapped admin, `FaultyStorage`
installed as `KeyorixCore`'s storage.

1. **Setup** (unfaulted): `POST /api/v1/secrets/` creates a secret.
2. **Fault armed:** `(Method: "ListSecretDependenciesForProject", NthCall: 1,
   Kind: KindPanic)`.
3. **Execute:** `DELETE /api/v1/secrets/{id}`.
4. `core.DeleteSecret` calls `c.storage.DeleteSecret(ctx, id)`, which
   succeeds — the `SecretNode` row is gone.
5. `emitDependencyLifecycleEvents` calls `c.storage.ListSecretDependenciesForProject`,
   which panics on the injected fault.
6. The panic unwinds `DeleteSecret` entirely; the real `Recovery` middleware
   catches it and returns `500`.

**Oracle (a) violation:** the operation reported an ERROR (500), but logical
state changed anyway relative to the pre-Execute baseline — the `SecretNode`
table diverges (the secret is gone in the faulted run, exactly as it would be
in a genuinely successful delete, but the caller was told it failed).

Minimized input saved at
`server/faultops/testdata/fuzz/FuzzStorageFaultOperations/059212c4cda84764`,
replayable standalone via `REPLAY_HEX=<hex> go test ./server/faultops/... -run
TestReplayStorageFaultInput -v`.

## Impact

- **Caller confusion, not data loss in the dangerous direction**: the actual
  effect (secret deleted / secret restored) is exactly what a genuinely
  successful call would have produced — this is not a partial or
  inconsistent commit, and it is not a privilege or authorization issue. The
  defect is purely that the caller is told the opposite of what happened.
- **Operationally still real**: a caller told "delete failed" might retry the
  delete (harmless — the second attempt hits `GetSecret`'s not-found path and
  correctly reports an error, since the secret is already gone) or might
  believe the secret still exists and continue relying on it in a downstream
  system, when it has actually already been removed.
- **Likelihood:** requires a panic specifically (not a returned error) from
  the dependency-edge read during a delete/restore that has an incident
  dependency edge count to compute — a narrower trigger than a generic
  returned-error fault, but not adversarial: any panicking bug in that read
  path (a real storage-layer defect, not attacker-controlled input) would
  trigger this exact masking behavior.

## What this is NOT

- Not the F3 defect family (`docs/findings/2026-09-21-FINDING-role-update-permission-replace-swallows-storage-errors.md`)
  — no swallowed *error*, no authz-resolution fault, no ambiguous partial
  commit. This is specifically "a best-effort helper's panic-safety gap":
  correctly handles a returned error, does not correctly handle a panic from
  the identical call.
- Not an authz bypass — nothing here grants or extends access; if anything,
  the caller ends up MORE cautious than warranted (believing a delete failed
  when it succeeded), never less.

## Fix

`emitDependencyLifecycleEvents` now recovers from a panic during its
`ListSecretDependenciesForProject` call, logging a warning and returning —
the same "best-effort, never surface to the caller" contract its own doc
comment already promised, now actually enforced for both failure modes
(returned error and panic), not just one:

```go
func (c *KeyorixCore) emitDependencyLifecycleEvents(ctx context.Context, eventType string, actorID, secretID, projectID uint, secretName string) {
    defer func() {
        if r := recover(); r != nil {
            log.Printf("Warning: dependency-lifecycle event emission for secret %d panicked (best-effort, primary operation already succeeded): %v", secretID, r)
        }
    }()
    edges, err := c.storage.ListSecretDependenciesForProject(ctx, projectID)
    if err != nil {
        return // best-effort; the primary operation already succeeded
    }
    ...
}
```

No transport-layer change was needed — both `DeleteSecret` and
`RestoreSecret` already just call this one shared function.

### Second live occurrence: CreateUser's password-history seed and system_viewer auto-assign

A second unattended final-checks burst, run immediately after the fix above
landed, found the IDENTICAL shape on a completely different function:
`core.CreateUser` (`internal/core/users.go`) seeds password history and
auto-assigns the `system_viewer` baseline role (ADR-021) as two sequential
best-effort steps AFTER `c.storage.CreateUser` has already committed the new
user row — both discarded a returned error (`_ = ...`) but neither was
protected against a panic from the same call.

**Reproduction:** fault `(op="REST POST /api/v1/users/", method=AssignRole,
NthCall=1, kind=panic)`. `AssignRole`'s panic propagated through `CreateUser`,
past the already-committed `User` row (and, if password history is enabled,
past the already-committed `PasswordHistory` row too) and out to the real
Recovery middleware, producing a 500 for a request that had, in fact, already
succeeded — `Differing tables: [PasswordHistory User]`. Minimized input saved
at `server/faultops/testdata/fuzz/FuzzStorageFaultOperations/8ee52322e0585924`.

**Fix:** both best-effort steps in `CreateUser` are now wrapped in their own
`defer`/`recover`, logging a warning and continuing — the same treatment
`emitDependencyLifecycleEvents` received above, applied to the second live
instance of the identical shape.

### Third live occurrence: CreateProject/CreateProjectWithEnvs's environment seeding

Found 2026-09-23 by `FuzzStorageFaultOperations` running unattended against
`fix/1962-shared-fuzzworld` in CI (PR #1988) — coverage-guided fuzzing on the
refreshed shared `fuzzworld` harness landing in that PR, not a hand-written
seed. `core.CreateProject` (`internal/core/catalog.go`) already treated a
*returned error* from its default-environment-seeding `CreateEnvironment`
call as non-fatal/best-effort, with an explicit doc comment saying so — but,
identically to the first two occurrences above, had no protection against a
**panic** from that same call. `CreateProjectWithEnvs`'s requested-environment
seeding loop had the identical gap.

Worse, `internal/core/users.go`'s own comment (on the `system_viewer`
auto-assign fix, second occurrence above) already said "same class as
CreateProjectWithEnvs's CreateEnvironment fix above" — asserting this fix
already existed. It did not: the comment was aspirational/mis-stated, not a
description of shipped code, and nothing had re-verified it.

**Reproduction:** fault `(op="REST POST /api/v1/projects", method=CreateEnvironment,
NthCall=1, kind=panic)`. The panic propagated through `CreateProject`, past
the already-committed `Project` row, out to the real Recovery middleware,
producing a 500 for a request that had, in fact, already succeeded —
`Differing tables: [Project]`. Minimized input saved at
`server/faultops/testdata/fuzz/FuzzStorageFaultOperations/ad8a1c49b476fc19`
(hand-constructed via the harness's own `opCatalog`/`storageInterfaceMethodNames`
lookup and `decodeFuzzOp` byte layout to exactly reproduce CI's finding,
`REPLAY_HEX`-confirmed against the pre-fix commit before being fixed).

**Fix:** both environment-seeding loops (`CreateProject`'s default set,
`CreateProjectWithEnvs`'s requested set) now wrap their `CreateEnvironment`
call in the same IIFE-with-`defer recover()` idiom as the first two
occurrences, logging a warning and continuing — the harness's own
`acceptableByDesign` classification for `CreateEnvironment`
(`fuzz_storage_fault_operations_test.go`) now correctly covers the panic
path, not just the returned-error path.

### Proactive fix: emitAudit, the shared audit choke point

Given the SAME defect shape recurred live twice in immediate succession
(different functions, same root cause), a third site was fixed proactively
rather than waiting for a third live finding: `emitAudit`
(`internal/core/service.go`) is the single choke point every
`c.Log*`/`writeAuditEvent*` helper funnels through (confirmed by
`TestDirectLogAuditEventCallersAreSafe`) — every caller of those helpers is,
by construction, in the exact "primary operation already succeeded, only the
audit trail is being written" position this defect class targets. A panic
inside `emitAudit` (most plausibly from its own `c.storage.LogAuditEvent`
call) would propagate to EVERY one of those callers, all at once, the same
way F3b's unprotected audit write did before its own fix. `emitAudit` now
recovers a panic the same way it already handles a returned `LogAuditEvent`
error (logging with the existing `"SECURITY: ..."` prefix its error-handling
branch already uses), closing this for every audit-emitting call site in the
codebase in one fix, not sixty separate ones.

**FLAG FOR REVIEW (not swept here):** a repo-wide grep for `best-effort`
across `internal/core` still turns up roughly sixty comparable call sites
beyond the four fixed here (see `account.go`, `login_lockout.go`,
`dashboard.go`, `notifications.go`, `compliance_posture.go`, and many
others). This finding fixes the three the fuzzer actually landed a panic
fault on, plus the one shared choke point (`emitAudit`) whose leverage
justified a proactive fix once the pattern recurred live — not a systematic
panic-safety audit of every remaining "best-effort" helper in the codebase.
The third occurrence (`CreateProject`/`CreateProjectWithEnvs`) is itself
proof this list isn't self-policing: `users.go`'s own comment already
*claimed* that exact site was fixed, and it wasn't, until the fuzzer found
it live a second time. Whether the same gap recurs at any of the remaining
sixty sites is a real open question worth a dedicated sweep, not decided or
attempted here.

## Red-proof

Before the fix: `FuzzStorageFaultOperations`'s corpus entry
`059212c4cda84764` (`(REST DELETE /api/v1/secrets/{id},
ListSecretDependenciesForProject, NthCall=1, KindPanic)`) failed
deterministically against pre-fix `internal/core/secret_dependencies.go`.
Reverting just that file (`git checkout HEAD -- internal/core/secret_dependencies.go`,
i.e. the commit immediately before this fix) and re-running the corpus:
`059212c4cda84764` was the ONLY entry to fail, with the exact oracle (a)
message quoted above (`Differing tables: [SecretNode]`); every other corpus
entry (F3a-d's own, the AssignRole exemption's, and the rest of the
operation catalog) stayed green. Restoring the fix made the corpus fully
green again, confirmed by `go build ./...`, the fuzz corpus re-run, and the
`internal/core`/`server/http`/`server/grpc` suites (including `-race`) —
all clean.

Second occurrence: reverting `internal/core/users.go` and
`internal/core/service.go` together (`git checkout HEAD -- internal/core/users.go
internal/core/service.go`, the commit immediately before this second fix)
and re-running the corpus reproduced `8ee52322e0585924` exactly, with every
other corpus entry (including `059212c4cda84764` from the first fix, still
present) staying green. Restoring both files made the corpus fully green
again, confirmed by `go build ./...`, the fuzz corpus re-run, and the
`internal/core`/`server/http`/`server/grpc` suites (including `-race`) —
all clean. `emitAudit`'s own fix had no dedicated fuzz-found trigger (it was
proactive, not reactive) — its correctness rests on the same `-race` suite
pass plus the existing `TestDirectLogAuditEventCallersAreSafe` guard
continuing to pass unchanged.

Third occurrence: reverting `internal/core/catalog.go` alone (`git stash`
just that file, the commit immediately before this third fix) and re-running
`FuzzStorageFaultOperations/ad8a1c49b476fc19` in isolation reproduced the
exact `ORACLE (a) VIOLATION ... Differing tables: [Project]` message quoted
above, deterministically. Restoring the file made that corpus entry (and the
full `server/faultops`, `internal/core`, and
`server/http/handlers` -run CreateProject* suites) pass again; `go build
./...` and `go vet ./...` stayed clean throughout.

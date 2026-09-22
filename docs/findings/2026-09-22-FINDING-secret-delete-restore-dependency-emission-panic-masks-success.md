# FINDING: a panic inside DeleteSecret's/RestoreSecret's best-effort dependency-lifecycle audit emission masks an already-successful delete/restore as a failed request

**Date:** 2026-09-22
**Component:** `internal/core/secret_dependencies.go` (`emitDependencyLifecycleEvents`),
called from `internal/core/secrets.go`'s `DeleteSecret` and `RestoreSecret`.
**Status:** Fixed, same PR as this finding doc (policy change: first-party
findings are fixed and disclosed together — no customers yet).

Found by an unattended final-checks fuzz burst (`FuzzStorageFaultOperations`,
`server/faultops`), run after coverage batch 6 landed — not a hand-written
seed.

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

**FLAG FOR REVIEW (not swept here):** a repo-wide grep for `best-effort`
across `internal/core` turns up roughly sixty comparable call sites (see
`account.go`, `login_lockout.go`, `dashboard.go`, `notifications.go`,
`compliance_posture.go`, and many others) — this finding fixes the ONE the
fuzzer actually landed a panic fault on, not a systematic panic-safety audit
of every "best-effort" helper in the codebase. Whether the same
returned-error-only gap recurs at any of those other sites is a real open
question worth a dedicated sweep, not decided or attempted here — consistent
with this campaign's own "check fix siblings, not just original site"
practice applied narrowly (siblings of the *exact* call this fuzz burst
found), not stretched into an unrelated, much larger audit mid-task.

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

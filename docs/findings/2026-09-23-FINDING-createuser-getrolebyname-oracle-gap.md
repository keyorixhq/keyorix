# FINDING: fuzz oracle's non-fatal exemption for CreateUser's baseline role grant only named one of its two storage calls

**Date:** 2026-09-23
**Component:** `server/faultops/fuzz_storage_fault_operations_test.go`
(`opScopedBestEffortTables`) — test infrastructure only, no production code
changed.
**Status:** Fixed, same PR as this finding doc.
**Severity:** None (not a security or correctness defect) — this is a
false-positive in the fuzz oracle's own exemption list, triaged and closed
as an incidental out-of-scope observation from `fix/breakglass-revoke-atomicity`
(PR #2018).

## Summary

Flagged during PR #2018's own 10-minute fuzz-validation burst as an
unrelated, out-of-scope observation (deliberately not committed there — see
that PR's finding doc, "Out-of-scope observation, not fixed here"). Triaged
here per instruction.

`internal/core/users.go`'s `CreateUser` auto-assigns the baseline
`system_viewer` role (ADR-021) inside a nested `tx.WithTransaction`
(PostgreSQL SAVEPOINT, landed today in PR #1996) as a deliberately non-fatal
step:

```go
// pre-existing, unmodified by this fix
if err := tx.WithTransaction(ctx, func(savepoint storage.Storage) error {
    role, err := savepoint.GetRoleByName(ctx, "system_viewer")
    if err != nil {
        return err
    }
    return savepoint.AssignRole(ctx, createdUser.ID, role.ID, Scope{})
}); err != nil {
    log.Printf("Warning: user %d (%s) created without its baseline system_viewer role: %v", createdUser.ID, createdUser.Username, err)
}
```

This makes **two** storage calls before either can fail: `GetRoleByName`
then `AssignRole`. The fuzz oracle's `opScopedBestEffortTables` already had
an exemption for a fault landing on the *second* call
(`{op: "REST POST /api/v1/users/", method: "AssignRole", tables:
[]string{"UserRole"}}`, added during an earlier "coverage-batch-6" burst) —
but not the first. Faulting `GetRoleByName` instead produces the
byte-for-byte identical, equally intentional outcome (role lookup fails,
`AssignRole` is never reached, the user is still created, the failure is
still logged) — but with no matching exemption, the oracle reported it as a
violation.

## Reproduction

Seed reconstructed from the `input=%x` trace PR #2018 logged (the original
finding was deliberately not committed there): raw bytes `\x06A\xff`,
decoding to `op="REST POST /api/v1/users/"`, `fault=(GetRoleByName, NthCall=1,
kind=error)`.

```
op=REST POST /api/v1/users/ fault=GetRoleByName#1/error: ORACLE (a)
VIOLATION — reported SUCCESS but final state does not match the fault-free
reference run's state (partial/incorrect commit). Differing tables: [UserRole]
```

Confirmed red on current `origin/main` (which already includes PR #1996,
merged earlier today) before this fix; confirmed green after, with the
oracle correctly logging `ACCEPTABLE-BY-DESIGN` instead. Committed as
`server/faultops/testdata/fuzz/FuzzStorageFaultOperations/a506a678b50514c8`
(same name the original discovery used, for continuity with PR #2018's own
finding doc, which cites this exact identifier).

## Is this new since PR #1996? No.

PR #1996 fixed a *different* problem: on PostgreSQL, a failed statement
aborts the enclosing transaction at the protocol level, so the non-fatal
role-grant step needed its own SAVEPOINT (`tx.WithTransaction` nested inside
the outer `CreateUser` transaction) to keep a real constraint violation from
silently failing the whole `CreateUser` call. That fix is working correctly
here — the fault is contained, the user is created, the failure is logged.
This finding is about the fuzz harness's own oracle exemption list being
incomplete for the *already-correct* non-fatal design, not about anything
#1996 changed or introduced. The underlying non-fatal-baseline-role design
itself predates #1996 (ADR-021).

## Why the oracle, not the code, should change

- The code's own doc comment (`users.go`, immediately above the block above)
  already states the intended contract explicitly: "Non-fatal... the user
  row itself already committed, and both failure modes — a returned error
  AND a panic... must be OBSERVABLE, not swallowed, even though the user is
  still created regardless." A fault on `GetRoleByName` satisfies this
  contract exactly: observable (the `Warning` log line), non-fatal (201
  response), and the only state divergence is the intentionally-skipped role
  grant.
- Direction is security-benign, matching `opScopedBestEffortTables`'s
  existing `AssignRole` entry: failure means the new user ends up with
  *fewer* roles than the reference run (fail-closed, under-privileged),
  never more.
- Widening the *code* to add its own redundant handling here would add
  nothing — the SAVEPOINT and logging are already correct and already
  tested (`TestCreateUser_PostgresSavepoint_RoleAssignFailureIsNonFatal`,
  `internal/core/create_ops_pg_savepoint_test.go`, unaffected by this fix).
  The actual gap was purely in the test oracle's own enumeration of which
  calls belong to this already-correct non-fatal block.

## Fix

`server/faultops/fuzz_storage_fault_operations_test.go`: added a sibling
`opScopedBestEffortTables` entry, `{op: "REST POST /api/v1/users/", method:
"GetRoleByName", tables: []string{"UserRole"}}`, with a doc-comment addendum
explaining the incomplete-enumeration root cause and why the scoping is
still safe (not a blanket suppression):

- `GetRoleByName` is called exactly once during `CreateUser` — confirmed via
  `grep`, the op is wired to `opCatalog["CreateUser"]` only
  (`inventory_overrides_test.go`), and `CreateUser` (`users.go:154`) has no
  other `GetRoleByName` call site.
- The codebase's other two `GetRoleByName` call sites
  (`CreateUserWithAssignments`, `resolveProjectRoleGrant`) are separate
  functions, unreachable from this specific op, so this entry cannot mask a
  fault on a load-bearing `GetRoleByName` call the way a bare method-only
  `bestEffortTables` entry would risk (the same reasoning the pre-existing
  `AssignRole` entry's own doc comment already gives for scoping by op, not
  just method).

## Tests

- `server/faultops/testdata/fuzz/FuzzStorageFaultOperations/a506a678b50514c8`
  (regression seed, committed; red before, green after).
- Full `internal/core` and `server/faultops` suites pass with no
  regressions. `golangci-lint run ./server/faultops/...`: no issues.
  (`gosec` was not run against this package meaningfully — `server/faultops`
  contains only `_test.go` files, which gosec skips by design, and this fix
  touches no production code.)

## Out-of-scope observation from this triage's own short fuzz burst

A 3-minute validation burst on this branch (based on pre-#2018 `origin/main`)
surfaced `op="REST POST /api/v1/system/break-glass/{id}/revoke"
fault=(RevokeBreakGlassActivation, NthCall=1, kind=error)`, oracle (a),
`Differing tables: [UserRole AuditEvent]`. This is **not new** — it is the
mirror-direction half of the exact defect PR #2018 already fixes (role
removed by an independent first call, activation-state update fails on the
second, no shared transaction to roll either back). PR #2018's
`RevokeBreakGlassActivationAtomic` wraps both calls in one
`storage.WithTransaction`, which closes this direction too, not just the
`RemoveRole`-first direction PR #2018's own seed demonstrated. Not committed
here — it belongs to #2018's already-landed fix, not this PR, and would be
redundant/confusing to duplicate in a branch based on pre-#2018 `main`.

# TRIAGE: `REST POST /api/v1/projects/{id}/secrets/bulk-delete`, fault on `GetUserGroupRoleIDsAt` — not a bug, a harness-oracle gap specific to partial-success bulk ops

**Status:** closed, no production fix needed — the underlying authorization chain is
confirmed fail-closed by a new deterministic test (`internal/core/bulk_delete_authz_fault_test.go`).
This is a triage record, not a FINDING: nothing in production code is wrong.

**Original reports:** `~/proj/prompts/reports/SESSION-AT.md`, "Round 3" (first confirmation,
from a 20s exploratory fuzz run, not seeded/committed) and "Round 4" (second, independent
confirmation, also not seeded). Both report the same one-line summary and neither traces
root cause:

> `REST POST /api/v1/projects/{id}/secrets/bulk-delete`, fault on `GetUserGroupRoleIDsAt#2`,
> ORACLE (c) violation — a fault on an authz-resolution read inside bulk-delete produces a
> successful response instead of an error/deny.

## What was checked (this session, 2026-10-02)

Neither report left a replayable seed, and `REST POST /api/v1/projects/{id}/secrets/bulk-delete`
is not wired into `server/faultops`'s `opCatalog` on `main` at all (confirmed:
`rg -n "bulk-delete|BulkDelete" server/faultops/*.go` finds nothing) — the finding cannot be
replayed via the fuzz harness as it exists on this branch. Reproduced the underlying
authorization question directly instead, bypassing the harness, by tracing every storage
call `BulkDeleteSecrets` → `GetSecretWithPermissionCheck`/`DeleteSecretWithPermissionCheck` →
`CheckSecretPermission` can reach that resolves a role through group membership:

1. `CheckGroupPermissions` (secret-level GROUP SHARES) calls `GetUserGroupsAt`, not
   `GetUserGroupRoleIDsAt` — not the method the finding names.
2. `CheckSecretPermission`'s RBAC fallback (project-level ROLES, including group-granted
   ones) calls `AuthorizePrincipal` → `Authorize` → `scopedRoleIDs`, which calls
   `GetUserRoleIDsAt` *and* `GetUserGroupRoleIDsAt` — this is the real call site.
3. Every layer in that chain is already documented and implemented fail-closed:
   `Authorize`'s own doc comment ("Fails closed: any resolution error returns (false, err)"),
   `scopedRoleIDs` (`if err != nil { return nil, err }`), and `CheckSecretPermission`'s RBAC
   fallback (`if ok, aerr := ...; aerr == nil && ok` — an error makes the condition false and
   falls through to the final `return nil, fmt.Errorf(...insufficient permissions)`, never an
   accidental grant).

Wrote `TestBulkDeleteSecrets_GetUserGroupRoleIDsAtFault_NeverWronglyDeletes` to exercise this
end to end through the real entry point (not just the `Authorize` unit): a user whose *only*
path to `secrets.delete` on a project is a role (`project_developer`, not admin-tier) granted
through GROUP membership — no direct role, no ownership, no share, no ACL — attempts to
bulk-delete a secret they don't own, with `GetUserGroupRoleIDsAt` faulted on **every** call
(stronger than matching the fuzzer's exact reported call index — conclusive either way: if
faulting every call never produces a wrongful delete, no specific index could either). A
sanity sub-check first confirms the group-derived role genuinely grants delete with nothing
faulted, so the test isn't vacuously passing against a request that was always going to be
denied.

```
--- PASS: TestBulkDeleteSecrets_GetUserGroupRoleIDsAtFault_NeverWronglyDeletes (0.02s)
PASS
```

Result: `Deleted` is empty, `Failed` has exactly one entry, and the secret still exists
unchanged afterward — the fault is real (hit >0 times), and it never results in a wrongful
delete.

## Why oracle (c) still flags this (and why that's a harness gap, not a bug)

`BulkDeleteSecrets`'s own doc comment: "Partial success is allowed — individual failures are
collected in `Failed`." The HTTP handler (`server/http/handlers/secrets_bulk_delete.go`) calls
`h.sendSuccess(w, result, "")` **unconditionally** whenever `BulkDeleteSecrets` returns
`err == nil` — which it always does, even when every single item landed in `Failed`. This is
intentional, documented bulk-operation design, not an oversight.

`checkOracles`'s oracle (c) (`server/faultops/fuzz_storage_fault_operations_test.go`) treats
`in.result.Success` — the *whole operation's* reported outcome — as the signal: any
authz-resolution-method fault where `result.Success == true` is flagged, unconditionally,
unless a `nonLoadBearingAuthzReadExceptions` entry exists for the exact `(op, method, nth)`
triple. For a partial-success bulk op, `result.Success` is **always** `true` by design,
regardless of whether the specific item whose authz read was faulted was correctly denied —
the oracle cannot currently see per-item outcomes, only the envelope. Every bulk/compound op
with this shape (`BulkDeleteSecrets` here; the same applies in principle to bulk rename,
bulk-extend-expiring, bulk access-request approve/reject) would trip this oracle the same way
on any authz fault, correctly handled or not.

Not fixed here: `REST POST /.../bulk-delete` isn't wired into `opCatalog` on this branch, so
there is no live oracle check to fix yet, and the right general fix (teaching oracle (c) to
inspect `result.Failed`/per-item outcomes for ops whose `Driver` reports a bulk-result shape,
rather than adding a `nonLoadBearingAuthzReadExceptions` entry per call site) is a harness
design question for whoever wires bulk ops into the catalog — likely the SESSION-FI/AT5 track,
per the existing `knownOpenTolerances`/`onlyOutcomeLogTables` precedent oracle (a) already uses
for the identical "bulk op, one item's outcome differs" shape (PR #2393's bulk-reject-access-requests
NOTE).

## Verification
- `go build ./...`: clean
- `go vet ./internal/core/...`: clean
- `gofmt -l`: clean
- `golangci-lint run ./internal/core/...`: 0 issues
- `gosec -severity medium -exclude-generated ./internal/core/...`: 0 issues
- `go test ./internal/core/...`: clean (SQLite)

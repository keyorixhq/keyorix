# FINDING: DeleteSecret's audit-log name prefetch silently discarded its own permission-check error

**Date:** 2026-09-23
**Component:** `server/http/handlers/secrets_crud.go` (`DeleteSecret`).
**Status:** Fixed, same PR as this finding doc (first-party policy).
**Severity:** Low — see "Why this is Low, not a proven bypass" below; the
operation's real authorization decision was made correctly by an independent
call later in the same function, in every case observed.

Found by `FuzzStorageFaultOperations` (`server/faultops`) during unattended
verification of an unrelated fix (PR #1988) — corpus entry `52dd4afe85dd34bb`,
`fault=(method=RoleSetBypassesPermissionChecks, NthCall=2, kind=error)` on
`REST DELETE /api/v1/secrets/{id}`, not a hand-written seed.

## Summary

`DeleteSecret` pre-fetches the secret's name and project before deleting, so
the audit log can record something more useful than a bare id:

```go
// pre-fix
var prefetchErr error
var prefetched *models.SecretNode
if isMachine {
    prefetched, prefetchErr = h.coreService.GetSecret(r.Context(), uint(id))
} else {
    prefetched, prefetchErr = h.coreService.GetSecretWithPermissionCheck(r.Context(), uint(id), userCtx.UserID)
}
if prefetchErr == nil {
    secretName = prefetched.Name
    secretProjectID = prefetched.ProjectID
}
// prefetchErr is never checked again — falls straight through to the delete
```

For the non-machine path, `GetSecretWithPermissionCheck` is not just a
lookup — it is this route's own permission-resolution read (`internal/core/permissions.go`'s
`EnforceSecretReadPermission` → `CheckSecretPermission` → `roleSetContainsAdmin`
→ `storage.RoleSetBypassesPermissionChecks`, the same chain `Authorize` uses
everywhere else). `prefetchErr` was captured only to decide whether the audit
log got the real name; it never gated whether the delete proceeded.

## Reproduction (fuzzer trace)

```
op="REST DELETE /api/v1/secrets/{id}" fault=(method=RoleSetBypassesPermissionChecks, NthCall=2, kind=error)
ORACLE (c) VIOLATION — a fault on an authz-resolution read produced a
SUCCESSFUL result instead of an error/deny: HTTP 204
```

Traced call order for one `DELETE` request as an authenticated admin:
1. **Call #1** to `RoleSetBypassesPermissionChecks`: router middleware
   `RequireScopedSecretPermission` → `AuthorizeSecretPrincipal` — succeeds,
   route allowed.
2. **Call #2 (the faulted one):** the prefetch's `GetSecretWithPermissionCheck`
   → `EnforceSecretReadPermission` → `CheckSecretPermission`'s RBAC fallback →
   `roleSetContainsAdmin` → storage errors. `Authorize` correctly returns
   `(false, err)`; `CheckSecretPermission` wraps it as
   `"permission denied: insufficient permissions"` — still an error, but
   `prefetchErr` discards it.
3. **Call #3 (unfaulted — the fault fires once):** `DeleteSecretWithPermissionCheck`
   → `EnforceSecretOwnerPermission` → its own fresh `roleSetContainsAdmin` →
   `RoleSetBypassesPermissionChecks` call succeeds normally (real admin), so
   the delete's own gate passes legitimately → `204`.

Minimized input saved at
`server/faultops/testdata/fuzz/FuzzStorageFaultOperations/52dd4afe85dd34bb`,
replayable standalone via `REPLAY_HEX=04374338 go test ./server/faultops/...
-run TestReplayStorageFaultInput -v`.

## Why this is Low, not a proven bypass

`EnforceSecretReadPermission` (`PermissionRead`) and `EnforceSecretOwnerPermission`
(`PermissionOwner`, what `DeleteSecretWithPermissionCheck` actually gates on)
both funnel through the same `CheckSecretPermission`, whose level hierarchy
(`hasRequiredPermission`, `internal/core/permissions.go`) makes `PermissionOwner`
a strict superset of `PermissionRead` on every authorization path: a live
owner satisfies both unconditionally; a share/ACL/RBAC grant high enough to
pass the owner-level (delete) check is, by construction, also high enough to
pass the read-level check. So under real (non-fault-injected) operation, any
caller whose prefetch would be denied for a genuine permission reason is
*also* denied by `DeleteSecretWithPermissionCheck`'s own independent gate —
the swallowed error never actually let an unauthorized caller through in
practice, only a caller whose prefetch failed for a reason unrelated to their
own authorization level (the fault-injection scenario above; in production,
an equivalent transient storage hiccup on that one read).

That said, relying on a second, independent, mostly-redundant check to
silently paper over a discarded error from the first is fragile: it holds
only because the two permission levels happen to nest today. This is exactly
the shape of latent gap this codebase's fuzz harness exists to surface before
a future refactor (a permission model change, a new share type, a
project-scoped exception) breaks the nesting and turns a cosmetic bug into a
real one. Fixed now, at Low severity, rather than left as a documented
tolerance.

## What this is NOT

- Not a proven authorization bypass in the current codebase — see above. No
  caller was ever observed to delete a secret they were not independently
  authorized to delete.
- Not the same defect as `docs/findings/2026-09-23-FINDING-update-secret-read-error-swallowed.md`
  (a *different* handler's error swallowed into a wrong-but-benign default,
  `ErrorSecretNotFound`/version-numbering shape) — that finding is about a
  value silently defaulted; this one is about an authorization decision
  silently discarded in favor of a second, separate authorization decision.
  Same family (a real error treated as "proceed"), different mechanism.

## Fix

`DeleteSecret` now checks `prefetchErr` and aborts the request — matching
`GetSecret`'s handler (same file) treatment of the identical
`GetSecretWithPermissionCheck` error — **except** for `core.ErrAccessOutsideSchedule`,
which is deliberately exempted: a `SecretAccessSchedule` pins a READ window
(`secret_schedule.go`'s own doc comment: "reads outside the window are
rejected"), and `DeleteSecretWithPermissionCheck` never enforces it — deletion
is intentionally not schedule-gated. Aborting on it here would have newly
imposed a read-only restriction onto delete that the schedule feature was
never designed to cover; a first draft of this fix (mirroring `GetSecret`
verbatim) got this wrong before `internal/core/secret_schedule.go`'s doc
comment was checked.

## Tests

- `server/faultops/testdata/fuzz/FuzzStorageFaultOperations/52dd4afe85dd34bb`
  (fuzzer-found regression seed, committed; red/green confirmed against the
  pre-fix commit via `REPLAY_HEX`).
- `server/http/handlers/secrets_crud_delete_prefetch_error_test.go`:
  `TestDeleteSecret_NotBlockedByAccessSchedule` — a secret with an
  always-denying access schedule (`StartHour=EndHour=0`, `hour >= EndHour` is
  always true) can still be deleted; locks in the schedule carve-out
  specifically, red-confirmed by temporarily removing the
  `!errors.Is(prefetchErr, core.ErrAccessOutsideSchedule)` exemption (fails
  with a 500, and the secret is left undeleted) and green again with it
  restored.

## Red-proof

Reverting `secrets_crud.go`'s `DeleteSecret` to the pre-fix
`if prefetchErr == nil { ... }`-only form (no abort branch) and replaying
`52dd4afe85dd34bb` reproduces the exact `ORACLE (c) VIOLATION` above,
deterministically. Restoring the fix makes that corpus entry, the new
schedule-exemption test, and the full `server/http/handlers`,
`server/faultops`, and `internal/core` suites pass again; `go build ./...`
and `go vet ./...` stayed clean throughout.

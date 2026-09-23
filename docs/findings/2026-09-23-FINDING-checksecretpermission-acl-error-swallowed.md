# FINDING: CheckSecretPermission's ACL check swallows a real HasSecretACL error instead of propagating it

**Date:** 2026-09-23
**Component:** `internal/core/permissions.go` (`CheckSecretPermission`).
**Status:** Fixed, same PR as this finding doc.
**Severity:** Low — see "Why this is not a security bug" below. No authorization
decision is ever affected in the over-grant direction; this is an error-observability
defect that, at worst, wrongly DENIES a legitimate caller under a transient fault.

Found by `FuzzStorageFaultOperations` (`server/faultops`) during CI for a different,
unrelated PR (#1997) — corpus entry `b849072656caad1d`, `fault=(method=GetSecretAncestors,
NthCall=2, kind=error)` on `REST PUT /api/v1/secrets/{id}` (`UpdateSecret`).

## Summary

`CheckSecretPermission`'s per-secret ACL check discards a real error from `HasSecretACL`
instead of propagating it:

```go
// pre-fix
if hasACL, aerr := c.HasSecretACL(ctx, userID, secretID, aclPerm); aerr == nil && hasACL {
    return &PermissionContext{...}, nil
}
// falls through to the RBAC fallback regardless of whether aerr was nil or a real error
```

Compare `AuthorizeSecret` — the route middleware's equivalent path
(`RequireScopedSecretPermission` → `AuthorizeSecretPrincipal` → `AuthorizeSecret`,
`internal/core/authz.go`) — which handles the identical `HasSecretACL` call correctly:

```go
hasACL, err := c.HasSecretACL(ctx, userID, secretID, perm)
if err != nil {
    return false, err   // fails closed
}
```

This asymmetry is why the fuzz harness's fault on `GetSecretAncestors` (which
`HasSecretACL` calls to walk folder-inherited ACL grants) produced a 403 on
`NthCall=1` (the middleware's own `AuthorizeSecret` call — correct) but NOT on
`NthCall=2` (`CheckSecretPermission`'s own call, from inside `UpdateSecretWithPermissionCheck`
→ `EnforceSecretWritePermission` → `CheckSecretPermission`) — the second call silently
treated "the ACL check itself failed" as "no ACL grant found" and fell through to the
RBAC fallback, which happened to grant access for the fuzz-bootstrapped admin caller via
their own independent, unaffected-by-the-fault global admin role.

## Why this is not a security bug

Three-point reasoning:

1. **`HasSecretACL` itself already fails closed correctly.** It only degrades to
   `(false, nil)` for `storage.ErrUnsupportedByBackend` (a backend that doesn't support
   SecretACL at all — a real, intentional design case, not a fault); any other error —
   including a faulted `GetSecretAncestors` — is returned as a real `(false, err)`. The
   bug is entirely in how `CheckSecretPermission` handles that returned error, not in
   `HasSecretACL`'s own logic.
2. **ACL is purely additive** (per `secret_acl.go`'s own design doc, and this function's
   own comment: "a SecretACL grant... satisfies read/write independently of any project
   role"). It can only ever grant access BEYOND what RBAC alone would — never restrict.
   So silently treating "the ACL check errored" as "no additional grant" and falling
   through to the RBAC fallback produces EXACTLY the outcome "RBAC alone, ignoring ACL
   entirely" would produce for that request. It cannot cause an over-grant relative to
   what RBAC alone decides.
3. **Traced why the specific fuzz-caller's request still succeeded under the fault**:
   `Authorize` (the RBAC fallback's underlying call) grants immediately when the
   caller's role set contains the built-in `admin` role, regardless of requested scope
   (`internal/core/authz.go`, `roleSetContainsAdmin` short-circuit) — a real, legitimate,
   independent grant, unaffected by the ACL-layer fault. A caller with a genuine
   ACL-only grant and NO independent RBAC access would, under the identical fault, be
   wrongly **denied** — the safe-failure direction, not a bypass — but still wrong: they
   would see a generic "insufficient permissions" instead of the real underlying error,
   masking a transient storage fault as a permanent denial.

## Fix

`CheckSecretPermission`'s ACL block now checks `aerr` explicitly and propagates a real
error immediately, mirroring `AuthorizeSecret`'s exact handling of the identical call.
The `storage.ErrUnsupportedByBackend` degrade is untouched — it lives entirely inside
`HasSecretACL`/`aclGrantsPermission`, which still return `(false, nil)` for it, so
`CheckSecretPermission`'s new `if aerr != nil` check never fires for that case; it falls
through to the RBAC fallback exactly as before.

## Tests

`internal/core/permissions_acl_error_test.go` (new):

- `TestCheckSecretPermission_ACLReadErrorPropagates` — a caller with a genuine
  FOLDER-INHERITED ACL grant (so the direct-secret ACL check finds nothing and
  `HasSecretACL` must reach the faulted `GetSecretAncestors` call) and no independent
  RBAC access, under a faulted ancestor read, must get the real error back — not a
  silent "insufficient permissions" denial.
- `TestCheckSecretPermission_ACLGrantWithWorkingRead_Succeeds` — control: the identical
  fixture with a working (unfaulted) read grants access via the ACL path
  (`Source: "acl"`).
- `TestCheckSecretPermission_ACLUnsupportedBackend_StillFallsThroughToRBAC` — confirms
  the `ErrUnsupportedByBackend` degrade is untouched: a backend that doesn't support ACL
  at all still falls through to the ordinary RBAC-based denial, not a propagated error.

## Red-proof

Reverted only `permissions.go`'s fix (kept the new test file) and re-ran the three
tests: `TestCheckSecretPermission_ACLReadErrorPropagates` fails (`aerr` silently
discarded, no error returned) while the other two continue to pass — confirming the
tests exercise exactly this fix and nothing else. Re-applied the fix; confirmed green
again.

## Regression seed

The fuzz-found crasher that surfaced this (`b849072656caad1d`, discovered on `main`
during PR #1997's CI, unrelated to that PR's own diff) is **not** committed as a
regression seed in this PR: `FuzzStorageFaultOperations`'s own harness reproduces this
exact input deterministically from the encoded `(op, method, NthCall, kind)` bytes, and
replaying it against the fixed code was part of this fix's own verification — but the
corpus file itself lives in `server/faultops/testdata/`, a package this PR does not
otherwise touch, and the fault it exercises (`GetSecretAncestors` on `UpdateSecret`) is
now provably closed by `TestCheckSecretPermission_ACLReadErrorPropagates` above, which
exercises the identical code path directly and deterministically without depending on
fuzz-harness timing/corpus state. No `nonLoadBearingAuthzReadExceptions` (or any other
exception-list) entry ever existed for this `(op, method, NthCall)` triple — checked
directly in `server/faultops/fuzz_storage_fault_operations_test.go` before this fix; the
fuzz run simply failed outright in CI, which is how this was found.

## Sweep: the same error-shape elsewhere in internal/core and server/

Grepped `err == nil &&` / `aerr == nil &&` (and same-shaped variants) across
`internal/core` and `server/` for every hit near an authorization-relevant call
(`HasSecretACL`, `Authorize`/`AuthorizePrincipal`, `RoleSetHasPermission`,
`GetSecretAncestors`, share/grant lookups). Every hit, with verdict:

| Site | Shape | Verdict |
|---|---|---|
| `internal/core/permissions.go` (`CheckSecretPermission`'s ACL block) | `aerr == nil && hasACL` | **Fixed, this PR.** |
| `internal/core/permissions.go` (`CheckSecretPermission`'s RBAC fallback, same function, ~35 lines below) | `aerr == nil && ok` | Same superficial shape, **not the same bug**: this is the LAST check before the function's final "insufficient permissions" denial — no further fallback exists that a swallowed error could let fall through to. An error here just means "RBAC didn't grant either," which is what the function already concludes on a genuine RBAC denial. Not fixed. |
| `internal/core/authz.go` (readable-scopes enumeration, `~line 1130`) | `ok, aerr := c.AuthorizePrincipal(...)` then a SEPARATE `if aerr != nil { continue }` | Correct by construction — explicitly commented "Fail closed: skip scopes we cannot evaluate." Building a list of readable scopes; skipping an unevaluatable one is fail-closed for that scope specifically. Not the combined-condition shape at all. Not fixed. |
| `internal/core/secret_acl.go` (`HasSecretACL`'s own `GetSecretAncestors` call) | explicit `if err != nil { ... return false, err }`, degrading only `ErrUnsupportedByBackend` | Already correct — this is the function whose result `CheckSecretPermission` was mishandling; its own internals are fine and unchanged. |
| `internal/core/secret_move.go` (`GetSecretAncestors` for move-cycle detection) | `if err != nil && !errors.Is(err, storage.ErrUnsupportedByBackend) { return err }` | Correct — real errors propagate; not an authorization check (cycle detection) but confirmed fail-closed regardless. Not fixed. |
| `server/grpc/services/conversions.go` (`authorizeScopedTarget`'s real-404-exception check, `AuthorizedAtGlobalScope`'s gRPC counterpart) | `if allowed, err := cs.AuthorizePrincipal(...); err == nil && allowed { 404 } ; return 403` | Safe by construction: a swallowed error falls to the `403` (deny) branch, never grants — the ONLY thing this check decides is whether a nonexistent-target response is a genuine 404 or a generic 403 (#1645's anti-enumeration convention), not whether to grant an operation. Not fixed. |
| `server/middleware/auth.go` (`AuthorizedAtGlobalScope`, HTTP side, identical role) | `return err == nil && ok` | Same mechanism and same safe-direction verdict as the gRPC counterpart above. Not fixed. |
| `server/http/handlers/secrets_list.go` (`ListSecrets`'s scope/global RBAC-role-visibility fallback, two sites) | `if aerr == nil && scopeOK { <broader role-based listing> } else { <narrower owned+ACL listing> }` | Safe by construction: a swallowed error falls to the MORE RESTRICTIVE listing (owned + ACL-granted secrets only), never the broader role-based one. Under-grants on error, never over-grants. Not fixed. |
| `server/grpc/services/secret_service.go:365` (`GetSecretVersions`'s audit-only `GetSecretWithPermissionCheck` prefetch) | `if secret, sErr := s.core.GetSecretWithPermissionCheck(...); sErr == nil && secret != nil { <audit log only> }` | A REAL but DIFFERENT bug — the redundant-authz-prefetch pattern (a second, audit-only authorization call after the real authz gate already ran) — not the same swallowed-error-into-fallback shape this finding is about. Already being fixed on a separate, already-in-flight branch (`fix/redundant-authz-prefetch`, PR #1997) — not duplicated here. |

No other authorization-relevant call site matched the buggy shape.

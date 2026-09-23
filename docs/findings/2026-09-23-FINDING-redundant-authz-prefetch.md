# FINDING: an audit-only prefetch re-runs authorization a second time, making a harmless second failure look like a fail-open bug

**Date:** 2026-09-23
**Component:** `server/http/handlers/secrets_crud.go` (`DeleteSecret`);
`server/grpc/services/secret_service.go` (`DeleteSecret`, `GetSecretVersions`);
`server/faultops/fuzz_storage_fault_operations_test.go` (`nonLoadBearingAuthzReadExceptions`).
**Status:** Fixed, same PR as this finding doc.
**Severity:** Low / code-quality-and-observability — see "Why this is not a security
bug" below. No authorization decision was ever affected; the finding is redundant
work and a harness false-positive risk, not an access-control gap.

Found by `FuzzStorageFaultOperations` (`server/faultops`) across three separate
bursts, all tracing to the SAME root cause in `DeleteSecret`'s handler body:
`GetSecretAncestors#2` and `GetUserGroupRoleIDsAt#2` (already documented as
`nonLoadBearingAuthzReadExceptions` entries before this fix), and
`GetUserRoleIDsAt#2` (investigated and confirmed the same shape, not yet
excepted — see "Investigation" below). Regression seed:
`server/faultops/testdata/fuzz/FuzzStorageFaultOperations/a90ada564ac2204c`.

## Summary

`DeleteSecret` (REST) and its gRPC counterpart both make the SAME authorization
call twice per request:

1. The real authorization gate — the REST route's `RequireScopedSecretPermission`
   middleware, or gRPC's `authorizeSecretScoped` — runs first and fails closed on
   any error.
2. AFTER that gate has already passed, the handler body re-resolves the secret
   via `GetSecretWithPermissionCheck` a SECOND time, purely to populate the
   audit log's secret name/project ID. Its error is captured but deliberately
   non-fatal (`if prefetchErr == nil { ... }`, no else branch) — the delete
   proceeds regardless, falling back to a generic `id=%d` audit description.

`GetSecretVersions` (gRPC) has the identical shape: `authorizeSecretScoped`
authorizes the read, `GetSecretVersionsWithPermissionCheck` authorizes it AGAIN
to fetch the actual version list, and a THIRD authorization
(`GetSecretWithPermissionCheck`) runs purely to populate the audit log.

This redundant second (or third) call means `CheckSecretPermission` — and
everything it transitively reads (`GetSecretAncestors` for ACL inheritance,
`GetUserGroupRoleIDsAt`/`GetUserRoleIDsAt` for the RBAC fallback) — runs twice
per request. `FuzzStorageFaultOperations`'s oracle (c) faults each call in
turn and expects EVERY authz-resolution read to fail closed; a fault on the
SECOND, already-redundant call correctly still fails closed on the real
decision (the delete/read itself), but the harness's per-call model saw a
"successful result despite a faulted authz read" and flagged it as a
violation — because, from the harness's point of view, `GetUserRoleIDsAt`
(say) IS an authz-resolution read, and its 2nd call really did get faulted
while the surrounding operation really did succeed. The exception list existed
specifically to acknowledge "yes, that call is genuinely non-load-bearing" on
a case-by-case basis, rather than fixing the redundancy itself.

## Why this is not a security bug

The FIRST call to each of these methods — inside the real authorization gate
— is the one that decides access, and it fails closed on any fault (confirmed
by a fuzz run finding NO surviving violation at NthCall=1 for any of these
methods on either op). The second call's failure only degrades the audit log
(falls back to `id=%d` instead of the real name) — never the access decision.
This was already correctly reasoned through when the first two exceptions were
added; nothing here is a newly-discovered access-control gap. The reason to
fix it anyway: `CLAUDE.md`'s own standing lesson — "a redundant
prefetch-and-swallow pattern... could plausibly recur at other call sites" —
recurred exactly as predicted, a third time, and a growing ad-hoc exception
list is a worse shape than removing the redundant call it exists to excuse.

## Investigation

**Full enumeration of the pattern** (grepped every `*WithPermissionCheck` call
site across `server/http/handlers` and `server/grpc/services`, then manually
classified each as either a load-bearing operation call, whose error IS fatal,
or a candidate prefetch, whose error is silently swallowed for the SAME
resource an adjacent call already authorizes):

| Site | Role | Verdict |
|---|---|---|
| `secrets_crud.go:583` (REST `DeleteSecret`) | audit-only prefetch, error swallowed | **fixed** |
| `secret_service.go:249` (gRPC `DeleteSecret`) | audit-only prefetch, error swallowed | **fixed** |
| `secret_service.go:365` (gRPC `GetSecretVersions`) | audit-only prefetch, error swallowed | **fixed** |
| `secrets_crud.go:529` (REST `UpdateSecret` pre-diff fetch) | already uses plain `Storage().GetSecret`, not `*WithPermissionCheck` | already correct, unchanged |
| `secrets_versions.go:50` (REST `GetSecretVersions`) | already uses plain `GetSecret`, not `*WithPermissionCheck` | already correct, unchanged |
| `folders_handler.go:203` (`DeleteFolder`) | already uses plain `GetSecret` for its pre-delete type check | already correct, unchanged |
| `internal/core/bulk_delete.go:103` | per-item re-authorization; error IS fatal (`continue` to `Failed`), documented `#G31` design | different pattern, out of scope |
| Every other `*WithPermissionCheck` call site in both files | the load-bearing primary operation itself; error IS fatal | not a prefetch, out of scope |

**Requirement: no existence oracle.** Before changing any code, added
`server/http/redundant_authz_prefetch_no_oracle_test.go` — a fully-unauthorized
caller (a real user with zero role/share/ACL/global-permission grants anywhere)
must get a byte-identical response (status + body for REST; gRPC code +
message for gRPC) for an existing-but-inaccessible secret and a nonexistent
one, across all three sites. Run against the CURRENT (pre-fix) code first: all
three passed already — the real authz gate (`RequireScopedSecretPermission` /
`authorizeSecretScoped`) rejects a fully-unauthorized caller before the
handler body (and therefore the prefetch) is ever reached, for both the
existing and nonexistent case, via the shared `handleScopeResolutionError` /
`authorizeScopedTarget` mechanism (#1645's 403-for-both convention). This
means the fix below cannot regress the invariant either way — it changes code
downstream of where these tests already prove execution stops for an
unauthorized caller. The tests are committed anyway, to make that structural
fact machine-checked going forward rather than merely true today.

**Requirement: confirm `GetSecretVersions`'s returned data provenance.** Read
`secret_service.go`'s `GetSecretVersions` end to end: the response's `Versions`
field (`out`, built at lines 372-379 pre-fix) is populated ONLY from
`versions`, the result of `GetSecretVersionsWithPermissionCheck` (line 357).
The prefetch's `secret` variable is scoped inside its own `if` block (line
365) and used only inside the `goSafe` closure for `LogSecretReadWithProject`
— it never touches `out` or the returned `*pb.GetSecretVersionsResponse`.
Confirmed each gRPC path has a real, independent authz check ahead of both the
real op and the prefetch: `authorizeSecretScoped` (line 354 for
`GetSecretVersions`, line 242 for `DeleteSecret`) calls
`authorizeScopedTarget`, which calls `cs.AuthorizePrincipal` — a genuine
RBAC/ownership resolution, not a no-op, and structurally identical to the REST
side's `RequireScopedSecretPermission` gate. No site's returned data comes
from the prefetch; none needed to be left unchanged.

## Fix

All three sites: replace the `*WithPermissionCheck` prefetch with a plain,
unauthorized read (`GetSecret`) — matching every other already-correct
audit-only prefetch in this codebase (`UpdateSecret`'s pre-diff fetch,
`DeleteFolder`, REST `GetSecretVersions`). Authorization for the resource was
already established by the surrounding real gate; a second
`*WithPermissionCheck` call bought nothing but a second
`CheckSecretPermission` storage round trip (and, as this finding shows, a
harness false-positive risk).

`nonLoadBearingAuthzReadExceptions` is now empty. Both former entries are
unreachable, not merely inactive: `CheckSecretPermission` runs exactly once
per `DeleteSecret` request post-fix, so `NthCall=2` never occurs for either
method on this op again. The doc comment explaining the historical entries and
why they're gone is kept in place (not deleted outright) for the next person
who finds this pattern recurring elsewhere.

## Tests

- `server/http/redundant_authz_prefetch_no_oracle_test.go` (new): the three
  no-existence-oracle tests described above (`TestNoExistenceOracle_RESTDeleteSecret`,
  `TestNoExistenceOracle_GRPCDeleteSecret`, `TestNoExistenceOracle_GRPCGetSecretVersions`).
  Pass both before and after the fix (by construction — see "Requirement: no
  existence oracle" above).
- `server/faultops/testdata/fuzz/FuzzStorageFaultOperations/a90ada564ac2204c`
  (regression seed, committed): a `GetUserRoleIDsAt#2` fault on REST
  `DeleteSecret`. Passes against the fixed code.

## Red-proof

Restored ONLY the REST `DeleteSecret` prefetch to its pre-fix
`GetSecretWithPermissionCheck` form (`nonLoadBearingAuthzReadExceptions` left
EMPTY, as the fix leaves it) and replayed `a90ada564ac2204c`:

```
ORACLE (c) VIOLATION — a fault on an authz-resolution read produced a
SUCCESSFUL result instead of an error/deny: HTTP 204
op=REST DELETE /api/v1/secrets/{id} fault=GetUserRoleIDsAt#2/error
```

Confirms both halves of the fix are load-bearing together: removing the
prefetch is what stops `CheckSecretPermission` from running twice, and the
harness's own oracle (c) is what would have caught this shape had the
exception list been emptied WITHOUT also removing the redundant call — the
exception list wasn't the thing making this safe, the single-authorization-gate
behavior is. Re-applied the fix; confirmed green again (`go test
./server/faultops/... -count=1`).

Full `server/faultops`, `server/grpc/...`, and `server/http/...` suites pass
with no regressions.

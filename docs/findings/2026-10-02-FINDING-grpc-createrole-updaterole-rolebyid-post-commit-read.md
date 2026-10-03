# FINDING: gRPC `RoleService.CreateRole`/`UpdateRole` report the whole RPC as failed if the post-commit `roleByID` response-building read fails — even though the role (and its permission set) already committed successfully

**Date:** 2026-10-02
**Component:** `server/grpc/services/role_service.go` (`RoleGRPCService.CreateRole`
line 80-84, `RoleGRPCService.UpdateRole`'s equivalent tail at line 151,
both via the shared `roleByID` helper, line 302) → `core.GetRoleWithPermissions`
→ `storage.GetRole`.
**Status:** **Open, not fixed in this session** — found while wiring new
MFA opCatalog entries (SESSION-FI, AT5); out of that session's OWNS
(`server/faultops/**`, `internal/storage/migrations/**`,
`scripts/fuzzing/targets.d/**`), filed per the campaign's standing
practice of not fixing out-of-scope findings in the session that found
them.

## Summary

Same defect family as
`docs/findings/2026-09-21-FINDING-role-update-permission-replace-swallows-storage-errors.md`'s
**F3d** (a "compute the response" read placed AFTER the transaction that
produced the data it reads, instead of as the last statement inside it) —
but F3d's fix only moved `core.CreateRole`/`core.UpdateRole`'s OWN internal
`GetRolePermissions` call inside their respective transactions. It never
touched this SEPARATE, outer call the gRPC service layer makes on top:

```go
// RoleGRPCService.CreateRole:
role, _, err := s.core.CreateRole(ctx, actor.UserID, req.GetName(), req.GetDescription(), permIDs)
if err != nil {
	return nil, mapRoleError(err)
}
return s.roleByID(ctx, role.ID)   // <-- separate read, AFTER CreateRole's own transaction already committed

func (s *RoleGRPCService) roleByID(ctx context.Context, id uint) (*pb.Role, error) {
	role, perms, err := s.core.GetRoleWithPermissions(ctx, id)
	if err != nil {
		return nil, mapRoleError(err)
	}
	return roleToProto(role, perms), nil
}
```

`s.core.CreateRole` already committed the role row and its permission
bundle, inside one transaction, with audit events written after commit
(F3c/F3d's fix, working correctly). But the gRPC handler then makes a
SECOND, independent call (`roleByID` → `GetRoleWithPermissions` →
`storage.GetRole`) purely to build the `*pb.Role` response. If THAT call
fails, the handler returns an error to the client — indistinguishable from
"nothing happened" — even though the role was fully, successfully created
moments earlier.

## Reachability

Directly reachable via the gRPC `RoleService.CreateRole` RPC (any caller
holding `roles.write`), and — by identical code shape, see below — the
`RoleService.UpdateRole` RPC.

## Reproduction (fuzzer trace)

Found by `FuzzStorageFaultOperations`'s own exploration (not seeded),
`-fuzztime=15m`, failing at 39s:

```
input=583043 -> op="GRPC keyorix.v1.RoleService.CreateRole" fault=(method=GetRole, NthCall=1, kind=error) principal=admin (bootstrapped)
ORACLE (a) VIOLATION — reported an ERROR but logical state changed anyway (partial commit). Differing tables: [AuditEvent RolePermission Role]
```

Minimized input saved at
`server/faultops/testdata/fuzz/FuzzStorageFaultOperations/540ce20f8c63a8bd`,
replayable via `go test ./server/faultops/... -run
'FuzzStorageFaultOperations/540ce20f8c63a8bd' -v`.

1. **Setup:** none beyond the standard bootstrapped admin.
2. **Fault armed:** `(method=GetRole, NthCall=1, kind=error)`. `core.CreateRole`
   itself never calls `storage.GetRole` (confirmed by reading
   `internal/core/rbac_roles.go:112-159` — it calls `tx.CreateRole`,
   `tx.AssignPermissionToRole`, and `tx.GetRolePermissions`, never
   `GetRole`), so NthCall=1 lands on the FIRST `GetRole` call made anywhere
   during this RPC — which is `roleByID`'s, after `core.CreateRole` already
   returned successfully.
3. **Execute:** `RoleService.CreateRole` RPC with a name and a valid
   permission list.
4. `s.core.CreateRole` runs to completion: role row + permission bundle
   committed in one transaction, `LogRoleCreated`/`LogPermissionAssigned`
   audit events written after commit — all exactly as F3c/F3d intended.
5. `s.roleByID(ctx, role.ID)` → `core.GetRoleWithPermissions` →
   `storage.GetRole` hits the injected fault and returns an error.
6. The RPC returns an error to the client. The reference (fault-free) run,
   by contrast, successfully returns the created role — so the two runs'
   `Role`/`RolePermission`/`AuditEvent` tables are identical to each other
   (both have the new role committed), but the FAULTED run's client-visible
   outcome (RPC error) says otherwise: a caller who sees this error has no
   way to know the role was actually created, and might retry — potentially
   creating a SECOND role with a similar name, or being confused when a
   subsequent `ListRoles` shows a role they were told failed to create.

## Sibling: `RoleService.UpdateRole` (same shape, not independently fuzzer-confirmed)

`RoleGRPCService.UpdateRole` (`role_service.go:151`) ends with the
identical `return s.roleByID(ctx, req.GetId())` pattern, after its own call
into `s.core.UpdateRole` (already transactional per F3a/F3b's fix) returns
successfully. Reading the code, this is the same defect at the same choke
point (`roleByID`), so a `GetRole` fault on the first call during an
`UpdateRole` RPC should reproduce the same class of violation. **Not yet
independently confirmed by the fuzzer** — the corpus entry above only
exercises `CreateRole`; flagging this as the predicted sibling per "check
fix siblings, not just original site," not as an independently-reproduced
finding.

## Impact

- **Availability / caller confusion:** a transient storage error on the
  response-building read turns a fully successful create/update into a
  client-visible RPC failure, with the same retry-and-duplicate risk F3d
  already documented for the REST/core-internal case — just one layer
  further out, specific to the gRPC transport's own response-shaping code.
- **Likelihood:** same as every other finding in this family — any
  transient failure on this one read triggers it, no adversarial setup
  required.

## What this is NOT

- Not a repeat of F3a/F3b/F3c/F3d themselves — those are fixed, and this
  finding's own reproduction confirms `core.CreateRole`'s internal
  atomicity (Role + RolePermission + audit all commit or roll back
  together) is working correctly. This is a NEW call site one layer
  further out, introduced by the gRPC service's own convenience
  `roleByID`-after-mutate pattern, which F3d's fix never reached because it
  lives in `server/grpc/services/role_service.go`, not
  `internal/core/rbac_roles.go`.
- Not an authz bypass or privilege escalation.

## Suggested fix (not applied here)

Have `CreateRole`/`UpdateRole` build the gRPC response directly from the
values `core.CreateRole`/`core.UpdateRole` already return (`role`,
`assignedPermissions`/`finalPermissions` — both already available at the
call site, as REST's own `CreateRole` handler already does, see
`server/http/handlers/rbac.go:171-188`, which has no equivalent gap)
instead of discarding them and re-fetching via `roleByID`.

## Fix status

**Not fixed.** Tolerated in `server/faultops/fuzz_storage_fault_operations_test.go`'s
`knownOpenTolerances` (op=`GRPC keyorix.v1.RoleService.CreateRole`,
method=`GetRole`, kind=error) so the corpus entry above can be committed as
a permanent regression pointer without failing CI on an open, out-of-scope
finding — remove that tolerance entry when this is fixed, per its own doc
comment.

# FINDING: gRPC `UserService.CreateUser`'s post-commit `userToProto` response enrichment is best-effort against a `ProjectMembershipCounts` ERROR but not a PANIC — a panic there reports the whole RPC as failed even though the user (and its role/password-history rows) already committed

**Date:** 2026-10-02
**Component:** `server/grpc/services/user_service.go` (`UserGRPCService.CreateUser`
line 131, `userToProto`/`projectCounts` lines 248-278) →
`core.ProjectMembershipCounts` → `storage.CountProjectMembershipsByUsers`.
**Status:** **Open, not fixed in this session** — found while wiring new
MFA opCatalog entries (SESSION-FI, AT5); out of that session's OWNS
(`server/faultops/**`, `internal/storage/migrations/**`,
`scripts/fuzzing/targets.d/**`), filed per the campaign's standing
practice of not fixing out-of-scope findings in the session that found
them.

## Summary

Same "post-commit response-building call undoes a correctly-committed
write" family as this session's other two findings
(`2026-10-02-FINDING-grpc-createrole-updaterole-rolebyid-post-commit-read.md`),
but the failure mode here is a **panic**, not a returned error, and the
existing best-effort handling only covers the error case:

```go
func (s *UserGRPCService) CreateUser(...) (*pb.CreateUserResponse, error) {
	...
	u, err = s.core.CreateUserWithAssignments(grantCtx, coreReq, role, assignments, actor.UserID, ...)
	if err != nil {
		return nil, mapUserError(err)
	}
	resp.User = s.userToProto(ctx, u)   // <-- separate call, AFTER the user already committed
	return resp, nil
}

func (s *UserGRPCService) userToProto(ctx context.Context, u *models.User) *pb.User {
	counts := s.projectCounts(ctx, []uint{u.ID})
	return userToProtoWithCounts(u, counts[u.ID])
}

// projectCounts is best-effort: on error the counts are absent (zero).
func (s *UserGRPCService) projectCounts(ctx context.Context, ids []uint) map[uint]corestorage.MembershipCounts {
	if len(ids) == 0 {
		return nil
	}
	counts, err := s.core.ProjectMembershipCounts(ctx, ids)
	if err != nil {
		return nil
	}
	return counts
}
```

`projectCounts`'s own doc comment says it's "best-effort: on error the
counts are absent (zero)" — but that handling is an `if err != nil`
check only. There is no `recover()` anywhere between
`CountProjectMembershipsByUsers` and the gRPC transport's own
outermost panic-recovery interceptor. A panic (not a returned error)
from that storage call propagates all the way up through
`projectCounts` → `userToProto` → `CreateUser`, past the point where
`CreateUserWithAssignments` already fully committed the new user row
plus its role grant(s) and password-history seed. The caller sees an
`Internal` RPC error — the SAME signal as "nothing happened" — for a
user that was, in fact, fully created.

## Reachability

Directly reachable via the gRPC `UserService.CreateUser` RPC (any caller
holding `users.write` + the relevant `roles.assign` scopes for any
requested role/project assignment), whenever the post-commit
`ProjectMembershipCounts` call panics.

## Reproduction (fuzzer trace)

Found by `FuzzStorageFaultOperations`'s own exploration (not seeded),
continuing the same `-fuzztime` burst as this session's other two
findings, failing at 53s:

```
input=5900203231 -> op="GRPC keyorix.v1.UserService.CreateUser" fault=(method=CountProjectMembershipsByUsers, NthCall=1, kind=panic) principal=admin (bootstrapped)
ORACLE (a) VIOLATION — reported an ERROR but logical state changed anyway (partial commit). Differing tables: [UserRole AuditEvent User PasswordHistory]
```

Minimized input saved at
`server/faultops/testdata/fuzz/FuzzStorageFaultOperations/b3657c421acd8a8e`,
replayable via `go test ./server/faultops/... -run
'FuzzStorageFaultOperations/b3657c421acd8a8e' -v`.

1. **Setup:** none beyond the standard bootstrapped admin.
2. **Fault armed:** `(method=CountProjectMembershipsByUsers, NthCall=1,
   kind=panic)`.
3. **Execute:** `UserService.CreateUser` RPC with a password (the
   default, non-setup-link/non-OTP path), presumably with a role/project
   assignment (the `UserRole` table shows up in the diff).
4. `s.core.CreateUserWithAssignments` runs to completion: the `User` row,
   its `UserRole` grant, and its initial `PasswordHistory` seed all
   commit; `LogUserCreated`-shaped audit events are written.
5. `s.userToProto(ctx, u)` → `s.projectCounts` →
   `s.core.ProjectMembershipCounts` → `storage.CountProjectMembershipsByUsers`
   hits the injected panic. Nothing between the fault and the gRPC
   transport's own outermost recovery interceptor catches it.
6. The RPC returns `Internal` to the client. The reference (fault-free)
   run successfully returns the created user with its real membership
   counts — the two runs' `User`/`UserRole`/`PasswordHistory`/`AuditEvent`
   tables are identical to each other, but the faulted run's
   client-visible outcome says the create failed: a caller who sees this
   error has no way to know the user (and its role grant) already exist,
   and might retry — risking a duplicate-username conflict on retry, or
   simply being confused when a subsequent `ListUsers` shows an account
   they were told failed to create.

## Sibling: REST's `ListUsers`/`attachProjectCounts` (same error-only best-effort shape, lower severity)

`server/http/handlers/users_list.go`'s `attachProjectCounts` has the
identical "catches the returned error, not a panic" shape around the same
`ProjectMembershipCounts` call. Flagged per "check fix siblings, not just
original site," but its severity is structurally lower: `ListUsers` is a
read-only operation with nothing committed beforehand to misreport as
failed — a panic there would just fail the list request itself, not mask
an already-successful write. Not independently reproduced by the fuzzer in
this session.

## Impact

- **Availability / caller confusion, with a concrete duplicate-create
  risk:** same shape as this session's other two findings, but the retry
  risk is sharper here — a caller retrying a `CreateUser` call after a
  false failure can hit a UNIQUE constraint on username/email (confusing,
  but safe) or, if the retry uses a slightly different username, end up
  with two accounts for what was meant to be one provisioning request.
- **Likelihood:** a panic (vs. a returned error) from
  `CountProjectMembershipsByUsers` is a narrower trigger than this
  campaign's other findings, but the code path offers NO protection against
  one at all (not even the error-handling the function already has for
  its sibling returned-error case).

## What this is NOT

- Not an authz bypass or privilege escalation.
- Not specific to the `CountProjectMembershipsByUsers` storage method —
  the gap is generic to `projectCounts`/`userToProto`'s own call shape;
  any panic from ANYTHING `core.ProjectMembershipCounts` can reach would
  trigger the identical masking.

## Suggested fix (not applied here)

Wrap `projectCounts`'s `s.core.ProjectMembershipCounts` call in the same
"never let a best-effort enrichment panic past the point where the
primary operation already succeeded" `recover()` pattern
`internal/core/service.go`'s `emitAudit` already uses (see that function's
own doc comment, which cites this exact campaign's prior panic-masking
findings) — log the panic (`SECURITY:`-prefixed, matching `emitAudit`'s
own convention) and return a zero `MembershipCounts` for the affected
user(s), the same degraded-but-honest response `projectCounts` already
produces for its returned-error case.

## Fix status

**Not fixed.** Tolerated in `server/faultops/fuzz_storage_fault_operations_test.go`'s
`knownOpenTolerances` (op=`GRPC keyorix.v1.UserService.CreateUser`,
method=`CountProjectMembershipsByUsers`, kind=panic) so the corpus entry
above can be committed as a permanent regression pointer without failing
CI on an open, out-of-scope finding — remove that tolerance entry when
this is fixed, per its own doc comment.

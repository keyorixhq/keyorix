# FINDING: `isGlobalAdminRoleName` treats a `GetRole` storage error the same as "this role is not an admin role" — a transient storage failure during `CreateSoDPolicy`'s authority check is silently denied and logged as a security DENIAL, not surfaced as an infrastructure failure

**Date:** 2026-10-02
**Component:** `internal/core/sod.go` (`isGlobalAdminRoleName`, called by
`CreateSoDPolicy`)
**Status:** **Open, not fixed in this session** — found while wiring new
MFA opCatalog entries (SESSION-FI, AT5); out of that session's OWNS
(`server/faultops/**`, `internal/storage/migrations/**`,
`scripts/fuzzing/targets.d/**`), filed per the campaign's standing
practice of not fixing out-of-scope findings in the session that found
them.

## Summary

```go
func (c *KeyorixCore) isGlobalAdminRoleName(ctx context.Context, userID uint) string {
	ids, err := c.scopedRoleIDs(ctx, userID, Scope{})
	if err != nil {
		return ""
	}
	for _, id := range ids {
		role, rerr := c.storage.GetRole(ctx, id)
		if rerr != nil {
			continue
		}
		if isAdminRoleName(role.Name) {
			return role.Name
		}
	}
	return ""
}
```

A `GetRole` error for one of the actor's role IDs is silently skipped
(`continue`), not distinguished from "this role, successfully read, is not
an admin role." If the actor holds exactly one role and the single
`GetRole` call for it fails (a transient storage error, lock contention,
connection hiccup), the loop finds nothing, returns `""`, and
`CreateSoDPolicy` (`internal/core/sod.go:151`) reads that as "actor is not
an admin-tier principal" — denying a request from a genuine admin, and
recording the denial as a security event:

```go
if c.isGlobalAdminRoleName(ctx, actorID) == "" {
	c.writeAuditEventFailed(ctx, EventSoDPolicyCreated, actorPtr(actorID), nil, "",
		fmt.Sprintf("SoD policy create DENIED: actor %d is not an admin-tier principal", actorID))
	return nil, wrapSoDPermissionDenied(...)
}
```

The caller sees `403 Permission denied`, indistinguishable from an actual
unauthorized attempt — and the audit trail now contains a "DENIED: not
admin-tier" entry for a request that was never actually unauthorized, only
unable to complete a role lookup.

## Reachability

Directly reachable by any authenticated admin via `POST
/api/v1/sod/policies` (no `/system` proxy involved) whenever the one
`GetRole` call this check makes happens to fail — in production, any
transient storage error during that single read.

## Reproduction (fuzzer trace)

Found by `FuzzStorageFaultOperations`'s own exploration (not a seeded
input), `-fuzztime=10m`, failing at 47s:

```
input=89631f -> op="REST POST /api/v1/sod/policies" fault=(method=GetRole, NthCall=1, kind=error) principal=admin (bootstrapped)
ORACLE (a) VIOLATION — reported an ERROR but logical state changed anyway (partial commit). Differing tables: [AuditEvent]
```

Minimized input saved at
`server/faultops/testdata/fuzz/FuzzStorageFaultOperations/51c8af2323e50625`,
replayable via `go test ./server/faultops/... -run
'FuzzStorageFaultOperations/51c8af2323e50625' -v`.

1. **Setup** (unfaulted): none beyond the standard bootstrapped admin.
2. **Fault armed:** `(method=GetRole, NthCall=1, kind=error)`.
3. **Execute:** `POST /api/v1/sod/policies` as the bootstrapped admin
   (whose sole role is an admin-tier role).
4. `CreateSoDPolicy` → `isGlobalAdminRoleName` → `scopedRoleIDs` returns the
   admin's one role ID → the injected fault fires on that role's `GetRole`
   call → `continue` → loop ends → returns `""`.
5. `CreateSoDPolicy` treats `""` as "not admin," calls
   `writeAuditEventFailed` (a genuine, committed `AuditEvent` row), and
   returns a permission-denied error.
6. HTTP response: `403`. The oracle's reference (fault-free) run, by
   contrast, succeeds and writes a DIFFERENT `AuditEvent` (`SoD policy
   created`) — the two runs' `AuditEvent` tables diverge, and the faulted
   run reported failure while still writing a row, exactly the oracle (a)
   pattern.

## Why this is a real bug, not working-as-intended audit logging

`CreateSoDPolicy`'s own doc comment states "A denied attempt is itself
audited, distinctly from a successful create" — this is a deliberate
design for GENUINE denials (an actual non-admin attempting the action).
The bug is one layer up: `isGlobalAdminRoleName` cannot tell its caller
"I don't know" (a storage read failed) apart from "I checked, and this
role is not admin-tier" (a successful read that resolved to a non-admin
role). Both collapse to the same `""` return value, so a transient
infrastructure failure gets permanently misrecorded as a confirmed,
audited security denial attributed to a real admin — polluting the audit
trail with a false "non-admin attempted this" entry for what was actually
"the admin's legitimate request failed to complete."

## Impact

- **Audit trail integrity:** a security review reading this audit log
  would see "actor <admin-id> DENIED: not admin-tier" and reasonably
  conclude that account attempted an unauthorized action — it did not.
- **Availability:** an admin's legitimate `CreateSoDPolicy` call fails
  outright on a transient storage hiccup instead of surfacing as a retryable
  infrastructure error (`500`), with no distinguishing signal from an
  actual `403`.
- **Likelihood:** same shape as this campaign's other `GetRole`/authority-
  resolution-read findings — any transient failure on this one read
  triggers it, no adversarial setup required.

## What this is NOT

- Not a privilege escalation or authz bypass — the failure mode is
  fail-**closed** (denies a legitimate admin), not fail-open.
- Not specific to SoD policies structurally — `isGlobalAdminRoleName`'s
  error-swallowing shape (`continue` on a `GetRole` error) is local to this
  one function; whether sibling authority-check helpers elsewhere in
  `internal/core` have the same pattern was not surveyed as part of this
  finding (flagged for a future "check fix siblings" pass once this is
  fixed).

## Suggested fix (not applied here)

`isGlobalAdminRoleName` should propagate a `GetRole` error to its caller
(return `(string, error)`) instead of swallowing it into the same `""` a
successful-but-non-admin lookup produces, so `CreateSoDPolicy` can
distinguish "confirmed not admin" (403, and the denial audit log is
accurate) from "could not confirm" (500, no denial audit event — the
request simply failed, nothing to hold against the actor).

## Fix status

**Not fixed.** Tolerated in `server/faultops/fuzz_storage_fault_operations_test.go`'s
`knownOpenTolerances` (op=`REST POST /api/v1/sod/policies`,
method=`GetRole`, kind=error) so the corpus entry above can be committed as
a permanent regression pointer without failing CI on an open, out-of-scope
finding — remove that tolerance entry when this is fixed, per its own doc
comment.

# FINDING: `UpdateRole`/`CreateRole` are not atomic across their role-write and permission-replace/assign phases — a mid-request failure (swallowed error OR panic) leaves partial effects, including a committed audit trail, behind a non-2xx or falsely-200/201 response

**Date:** 2026-09-21 (F3a/F3b), 2026-09-22 (F3c)
**Component:** `server/http/handlers/rbac.go` (`RBACHandler.UpdateRole` /
`replaceRolePermissions`, and originally `RBACHandler.CreateRole`'s own
permission-assignment loop) and `internal/core/rbac_roles.go`
(`KeyorixCore.UpdateRole`/`KeyorixCore.CreateRole`, the former unconditionally
audit-logging before the handler even reaches permission replacement).
**Status:** **Fixed.** `core.UpdateRole` and `core.CreateRole`
(`internal/core/rbac_roles.go`) each now run their role-row write, the
permission-set replacement/assignment, and the resulting audit events inside
one `storage.WithTransaction`, with audit logged only after that transaction
commits. Both REST and gRPC call these two functions for every code path that
touches a role's permission set. Closure proven by
`FuzzStorageFaultOperations` (`server/faultops`), which is now the regression
test for F3a, F3b, and F3c — their KNOWN-OPEN tolerances have been removed
from the harness, and every seed/corpus input that found them now passes
clean. Red-proofed in both directions for all three: reverting the fix
locally reproduces each failure exactly as originally found; restoring it is
green again. Three distinct trigger mechanisms of the SAME root cause are
documented below — referred to together as **F3** in the originating task
brief:

- **F3a** (originally filed): `replaceRolePermissions` swallows every storage
  error from its own calls and the handler always replies 200 regardless.
- **F3b** (found later, same day, by an unattended 10-minute fuzz burst —
  see "Reproduction" below): the SAME code path, faulted with a **panic**
  instead of a returned error. The panic IS correctly caught by the real
  `Recovery` middleware and turned into a 500 — the HTTP-level response is
  honest this time — but `KeyorixCore.UpdateRole`'s own audit-log write
  (`LogRoleUpdated`, called synchronously, BEFORE `replaceRolePermissions`
  even runs) has already committed by the time the panic unwinds the request.
  The caller sees `500`, reasonably assumes nothing happened, while an
  `AuditEvent` row asserting "role updated" already exists.
- **F3c** (found 2026-09-22, coverage-batch-5 fuzz burst, sibling on
  `CreateRole` rather than `UpdateRole` — see "F3c" below): the REST
  `CreateRole` handler's own permission-assignment loop swallowed
  `AssignPermissionToRole` errors the same way F3a's `replaceRolePermissions`
  did, so a role could be created and reported `201` with a permission
  silently missing from the response (`"permissions":null`). Unlike F3a/F3b,
  the triggering fault landed on an *authz-resolution* call inside the
  assignment path, so this is an **oracle (c) violation** (a fault on an
  authz-resolution read produced a successful effect), not just oracle (a).

**Severity: Medium-High impact / straightforward likelihood** — see "Severity"
below.

Found by `FuzzStorageFaultOperations`'s seed corpus
(`server/faultops/fuzz_storage_fault_operations_test.go`), seeded directly at
`(op="REST PUT /api/v1/roles/{id}", method="RemovePermissionFromRole",
NthCall=1, kind=error)` — i.e. F3a was predicted from reading the code during
STEP 0 investigation and then confirmed live by driving the real HTTP handler
through a real router with a real SQLite-backed storage layer, a fault injected
at exactly the point the code review predicted, no mocking of the logic under
test.

## Summary

`RBACHandler.UpdateRole` (`rbac.go:290`), when the request body includes a
`permissions` field, calls `replaceRolePermissions` (`rbac.go:394-404`) after
the role's own `Description`/core-level update has already succeeded:

```go
func (h *RBACHandler) replaceRolePermissions(ctx context.Context, actorID, roleID uint, toAssign []*models.Permission) {
	existing, _ := h.coreService.Storage().GetRolePermissions(ctx, roleID)
	for _, ep := range existing {
		_ = h.coreService.RemovePermissionFromRole(ctx, actorID, roleID, ep.ID)
	}
	for _, perm := range toAssign {
		if err := h.coreService.AssignPermissionToRole(ctx, actorID, roleID, perm.ID, false); err != nil {
			log.Printf("Warning: could not assign permission %q to role %d: %v", perm.Name, roleID, err)
		}
	}
}
```

Every one of its three storage-facing calls drops its error on the floor:

- `GetRolePermissions`'s error is discarded (`_`) — a storage failure here
  silently proceeds with `existing == nil`, skipping the removal loop entirely
  (not itself catastrophic, but it means the function has no way to know it is
  already operating on stale/incomplete data).
- `RemovePermissionFromRole`'s error is discarded (`_`) inside the loop — a
  failure removing one of several existing permissions is silently ignored and
  the loop continues to the next one.
- `AssignPermissionToRole`'s error is only **logged**
  (`log.Printf("Warning: ...")`), never returned or otherwise surfaced.

`replaceRolePermissions` itself returns nothing (`func(...) ` — no return
value), so **none of this is observable by its caller.** `UpdateRole`
(`rbac.go:368-372`) calls it and then unconditionally proceeds to
`sendSuccess(w, ..., "Role updated successfully")` — **HTTP 200**, regardless
of whether every single storage call inside `replaceRolePermissions` just
failed.

## Reachability

Directly reachable by any authenticated caller with `roles.write` (or
equivalent admin bypass) via `PUT /api/v1/roles/{id}` with a `permissions`
field in the body — an ordinary, undisguised REST call, not a `/system` proxy
or any other unusual path. `TestOperationCatalogKeysAreRegistered`
(`server/faultops/opcatalog_test.go`) keeps this operation's registry entry
from drifting from the live route.

## Reproduction (fuzzer trace)

World: fresh in-memory SQLite, one bootstrapped admin, `FaultyStorage`
installed as `KeyorixCore`'s storage.

1. **Setup** (unfaulted): `POST /api/v1/roles/` creates a role named
   `fuzz-role` with exactly the permission `secrets.read`.
2. **Fault armed:** `(Method: "RemovePermissionFromRole", NthCall: 1, Kind:
   KindError)`.
3. **Execute:** `PUT /api/v1/roles/{id}` with body
   `{"permissions": ["secrets.read"]}` (the same single permission — this
   reproduces with the trivial case, no need for a permission-set change to
   trigger it).
4. Inside `replaceRolePermissions`, the loop's one `RemovePermissionFromRole`
   call hits the injected fault and returns the injected error. The error is
   discarded. `AssignPermissionToRole` for `secrets.read` still runs
   afterward and succeeds (a fresh call, uncounted against the armed fault).
5. `UpdateRole` returns **HTTP 200** — `"Role updated successfully"`.

**Oracle (a) violation:** the operation reported SUCCESS, but the resulting
database state does **not** match the state a genuinely fault-free run of the
identical request produces — the `AuditEvent` table diverges between the two
worlds (the reference run and the faulted run took different internal paths
through the same nominally-successful code, and that divergence is only
visible by direct database inspection, not from the HTTP response, which is
identical `200 {"message":"Role updated successfully"}` in both cases). A
caller has no way to distinguish "the update fully succeeded" from "the
update partially failed, the caller error-logged it, but told you it worked" —
they are the same HTTP response.

### F3b: panic on the same call site (found by the unattended fuzz burst)

`GOMAXPROCS=2 go test ./server/faultops/... -fuzz=FuzzStorageFaultOperations
-fuzztime=10m` (the STEP 1 final-checks fuzz burst, no seed involved — this
was discovered by the fuzzer exploring on its own) found a second failing
input at 6m24s: `(op="REST PUT /api/v1/roles/{id}", method=
"RemovePermissionFromRole", NthCall=1, kind=panic)` — same setup as F3a, but
the injected fault PANICS instead of returning an error.

1. **Setup** (unfaulted): identical to F3a.
2. **Fault armed:** `(Method: "RemovePermissionFromRole", NthCall: 1, Kind:
   KindPanic)`.
3. **Execute:** identical `PUT /api/v1/roles/{id}` request.
4. `KeyorixCore.UpdateRole` (`internal/core/rbac_roles.go:128`) runs FIRST —
   `c.storage.UpdateRole(ctx, role)` succeeds (nothing meaningfully changes
   since this request sends no `description`, but the row IS touched), then
   `c.LogRoleUpdated(...)` writes an `AuditEvent` row **synchronously,
   unconditionally** — this is BEFORE the handler even calls
   `replaceRolePermissions`.
5. `replaceRolePermissions`'s `RemovePermissionFromRole` call panics on the
   injected fault. `FaultyStorage`'s `KindPanic` panics immediately, without
   ever invoking the real storage method — so the panic happens before any
   real permission removal.
6. The panic unwinds the whole request; the real
   `customMiddleware.Recovery()` (registered outermost, `server/http/router.go`)
   catches it and returns **HTTP 500**, honestly.
7. But `LogRoleUpdated`'s `AuditEvent` row from step 4 already committed and
   is never rolled back — it survives the panic that failed everything after it.

**Oracle (a) violation:** the operation correctly reported an ERROR (500),
but logical state changed anyway relative to the pre-Execute baseline — the
`AuditEvent` table gained a "role updated" row for a request whose overall
outcome the caller was told is a failure.

**Root cause, shared by F3a and F3b:** `UpdateRole`'s handler performs two
independently-committing phases — `core.UpdateRole` (role row + its own
unconditional audit write) and `replaceRolePermissions` (permission rows) —
with no transaction spanning both. F3a shows the permission-replace phase's
OWN errors get swallowed (reporting false success); F3b shows that even when
the permission-replace phase's failure IS correctly reported, the
role-update phase's effects (specifically its audit trail) are not
rolled back with it. Same non-atomicity, two different symptoms.

### F3c: the same swallow-and-log shape on `CreateRole` (found by coverage batch 5)

Wiring `REST POST /api/v1/roles/` into the operation catalog (coverage batch
2, per the RULES' stated priority order) and then running a fresh unattended
fuzz burst over it (coverage batch 5, rotation-policies) found a live third
sibling. Pre-fix `RBACHandler.CreateRole` created the role row first, then
looped over the caller's requested permissions:

```go
for _, perm := range toAssign {
    if err := h.coreService.AssignPermissionToRole(ctx, userCtx.UserID, role.ID, perm.ID, false); err != nil {
        log.Printf("Warning: could not assign permission %q to role %d: %v", perm.Name, role.ID, err)
    }
}
```

— the exact same discard-and-log shape as F3a's `replaceRolePermissions`,
just inline in the handler instead of a helper.

**Reproduction:** `input=24254d3030` → fault
`(method=RoleSetBypassesPermissionChecks, NthCall=4, kind=error)` on
`REST POST /api/v1/roles/` with a `permissions` field in the body. The fault
landed inside `AssignPermissionToRole`'s own authority-resolution path
(`failed to resolve actor authority: fault-fuzz injected failure`,
logged as a `Warning`, never returned). The handler still replied:

```
HTTP 201: {"data":{"permissions":null,"role":{"ID":11,"Name":"fuzz-role-batch2","Description":"fuzz role","BypassesPermissionChecks":false}},"message":"Role created successfully","success":true}
```

**Oracle (c) violation:** the fault fired on an authz-resolution read
(`AssignPermissionToRole`'s internal actor-authority check), and instead of
that read's failure blocking the effect it was gating, the caller still got
a successful `201` — the create went through, just silently missing the
permission grant the caller asked for and believed they got. This is
distinct from F3a/F3b's oracle (a) framing: here the swallowed failure is
specifically on the authorization-resolution step, not an ordinary storage
write, so a fail-closed-authz guarantee is what actually breaks.

**Root cause, same family as F3a/F3b:** `CreateRole`'s handler performed two
independently-committing steps (create the role row, then assign permissions
in a loop) with no transaction spanning both, and — like F3a — discarded
every `AssignPermissionToRole` error instead of aborting or reporting it.
gRPC's `CreateRole` already propagated this error correctly (the same
REST/gRPC asymmetry F3a had before its own fix), so this was REST-only.

## Impact

- **Availability of accurate authorization state:** an operator who issues
  `PUT /api/v1/roles/{id}` to change a role's permission set gets a `200
  Role updated successfully` even when the underlying removal/assignment
  partially failed. There is no error surfaced to the caller, no retry signal,
  and nothing in the API response distinguishing this from a clean update.
- **Direction of the failure mode matters for severity**: because
  `AssignPermissionToRole` failures are only logged (not aborted), a role can
  end up **missing** a permission the caller believed they granted — a
  fail-*open*-adjacent gap only in the sense that the caller's mental model of
  the role's permissions is now wrong, not that unauthorized access is
  automatically granted. Conversely, a `RemovePermissionFromRole` failure
  leaves a **stale** permission the caller believed they revoked still
  attached to the role — this is the security-relevant direction: an admin
  believes they have narrowed a role's permissions and the system silently
  did not.
- **Likelihood:** straightforward — any transient storage error (connection
  hiccup, lock contention, a constraint violation on a race with another
  concurrent role mutation) during this specific multi-call sequence triggers
  it. No unusual timing or adversarial setup required, unlike some of this
  campaign's other findings.

## What this is NOT

- Not a `/system` proxy issue — this is the ordinary, non-proxy REST path.
  (The `/system` proxy bypass class — handlers calling
  `coreService.Storage()` directly instead of going through `core.*` — is a
  separate, broader architectural pattern noted in the STEP 0 investigation
  report; this specific finding happens to also call `.Storage()` directly,
  but the defect here is the *dropped errors*, not the direct-storage-access
  pattern itself, which is otherwise a supported convention elsewhere in this
  handler package.)
- Not an authz bypass — the caller must already hold `roles.write` (or
  equivalent) to reach this code at all; nothing here grants unauthorized
  access on its own.

## Fix status

**Fixed**, same PR as this finding doc (policy change: first-party findings
are fixed and disclosed together now — no customers yet). `core.UpdateRole`
(`internal/core/rbac_roles.go`) was rewritten to accept an optional
`newPermissionIDs *[]uint` and run the role-row update, the permission
add/remove diff, and the resulting audit events inside a single
`storage.WithTransaction` call — `tx.RemovePermissionFromRole`/
`tx.AssignPermissionToRole` (the raw storage-interface calls, not the
authz/audit-wrapped core-level ones) run inside the transaction; every audit
event (`LogRoleUpdated`, `LogPermissionRemoved`, `LogPermissionAssigned`) is
written only AFTER that transaction commits, closing F3b's exact gap (an
audit write surviving a rolled-back transaction).

`server/http/handlers/rbac.go`'s `replaceRolePermissions` is deleted — its
authorization-resolution half (`authorizeAndCollectPermissions`, "does the
actor hold this permission themselves") stays in the handler (a read-only
decision, not a write, so it correctly runs BEFORE the transaction), but the
actual removal/assignment loop is gone, replaced by a single call into the
new atomic `core.UpdateRole`.

`server/grpc/services/role_service.go`'s `UpdateRole` had the same
non-atomic two-phase shape (though, unlike REST, it already propagated its
own permission-replace errors correctly) — it now calls the same
`core.UpdateRole`, removing its own duplicated
`RemovePermissionFromRole`/`AssignPermissionToRole` loop.

**F3c fix:** `core.CreateRole` (`internal/core/rbac_roles.go`) was rewritten
to accept `permissionIDs []uint` and run `tx.CreateRole` plus every
`tx.AssignPermissionToRole` call inside one `storage.WithTransaction`;
`LogRoleCreated`/`LogPermissionAssigned` are written only after that
transaction commits. `server/http/handlers/rbac.go`'s `CreateRole` handler
now computes `permissionIDs` from its already-authorized `toAssign` list and
calls the new core signature, deleting its own swallow-and-log loop.
`server/grpc/services/role_service.go`'s `CreateRole` now calls the same
`core.CreateRole`, removing its own (previously-correct) per-permission
assignment loop for symmetry with the REST path.

## Red-proof

Before the fix: `FuzzStorageFaultOperations`'s seed at `(REST PUT
/api/v1/roles/{id}, RemovePermissionFromRole, NthCall=1, KindError)` fired
**F3a** deterministically on every run against pre-fix `main`
(`server/http/handlers/rbac.go`, commit `bb93b549`). The `-fuzztime=10m`
burst independently rediscovered the same call site with a panic fault and
produced **F3b**, minimized to `input=8001539619a0178cee0000` — saved at
`server/faultops/testdata/fuzz/FuzzStorageFaultOperations/bdbfad52d4cc7bae`,
replayable standalone via `REPLAY_HEX=8001539619a0178cee0000 go test
./server/faultops/... -run TestReplayStorageFaultInput -v`.

After the fix: both directions verified locally — `git checkout <pre-fix
commit> -- internal/core/rbac_roles.go internal/core/rbac_roles_test.go
server/http/handlers/rbac.go server/grpc/services/role_service.go` (reverting
just the fix, not the harness) reproduces both F3a and F3b exactly as
originally found; restoring the fix makes both pass again, with no
KNOWN-OPEN tolerance needed. The two tolerance entries that used to live in
`server/faultops/fuzz_storage_fault_operations_test.go`'s
`knownOpenTolerances` are removed — the fuzzer itself is now the permanent
regression test for both.

**F3c:** minimized to `input=24254d3030`, saved at
`server/faultops/testdata/fuzz/FuzzStorageFaultOperations/c600067cf4d3bb8e`,
replayable standalone via `REPLAY_HEX=24254d3030 go test
./server/faultops/... -run TestReplayStorageFaultInput -v`. Red-proofed by
reverting just `internal/core/rbac_roles.go`,
`server/http/handlers/rbac.go`, and `server/grpc/services/role_service.go`
to their pre-fix state (`git checkout HEAD -- <files>`, i.e. the commit
immediately before this fix landed) and re-running the corpus:
`FuzzStorageFaultOperations/c600067cf4d3bb8e` was the ONLY corpus entry to
fail, with the exact oracle (c) message quoted above
(`"permissions":null` / `201`); every other corpus entry (F3a's, F3b's, and
the rest of the operation catalog) stayed green, confirming the revert's
blast radius was exactly this one call site. Restoring the fix (copying the
post-fix files back) made the corpus fully green again, confirmed by a full
`go build ./...`, `go vet ./...`, the `internal/core`/`server/http`/
`server/grpc` suites (including `-race`), and the fuzz corpus re-run — all
clean.

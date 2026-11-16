# Adversarial review — role-update path (UpdateRole)

Target: `KeyorixCore.UpdateRole` (`internal/core/rbac_roles.go`) + its permission-replace
helpers, the HTTP handler `RBACHandler.UpdateRole` (`server/http/handlers/rbac.go`), and the
gRPC handler `RoleGRPCService.UpdateRole` (`server/grpc/services/role_service.go`).

Method: DISPROVE the code's own atomicity/error-handling claims. All findings below are
reasoned from code alone; where OBSERVING the effect needs storage to fail, that is noted.

---

## Finding 1 — HTTP UpdateRole reports 200 + "Role updated successfully" while the permission replacement partially or wholly fails

- **Classification:** SECURITY-DEFECT
- **Location:**
  - `server/http/handlers/rbac.go:394-404` (`replaceRolePermissions`)
  - `server/http/handlers/rbac.go:367-372` (call site + unconditional `sendSuccess`)
- **The wrong assumption:** The handler treats `replaceRolePermissions` as infallible. The
  helper returns `void`; it discards the remove error (`_ = h.coreService.RemovePermissionFromRole(...)`,
  line 397) and only *logs* assign errors (`log.Printf("Warning: could not assign ...")`,
  lines 400-402). The handler then calls `sendSuccess(..., "Role updated successfully")`
  unconditionally (line 372). The design comment at rbac.go:321-327 reasons only about the
  *authorization* pre-check preventing a partial strip; it does not reason about a *storage*
  failure in the mutation loop itself.
- **Concrete trigger scenario:** A `roles.write` holder sends
  `PUT /api/v1/roles/{id}` with `permissions: ["secrets.read","secrets.write"]` (both of which
  the actor holds, so `authorizeAndCollectPermissions` passes at line 331). The role already
  has permissions A, B, C. `replaceRolePermissions` removes A, B, C one by one, then begins
  adding secrets.read / secrets.write. If the storage layer fails partway (DB deadlock,
  connection drop, unique-constraint/transient error) during the *remove* loop or the *add*
  loop, the role is left with a partial/empty permission set. Worst case: every remove
  succeeds and every add fails → the role ends up with **zero** permissions. In every case
  the client receives **HTTP 200 and "Role updated successfully"**, and the just-audited
  `role.updated` event (written by `core.UpdateRole` at line 354, BEFORE the permission loop)
  claims the update happened. The operator believes the role now grants {secrets.read,
  secrets.write}; it actually grants nothing (or a partial set). This is a fail-open: a role
  that silently lost permissions can deny access that policy intends to allow, and an operator
  who re-grants based on the "success" response will not re-apply the intended set.
- **Reachability trace to a live caller:** `server/http/router.go:1003` —
  `r.With(customMiddleware.RequirePermission(permRolesWrite)).Put("/{id}", rbacHandler.UpdateRole)`.
  Live route `PUT /api/v1/roles/{id}`, gated by `roles.write`. Directly reachable by any
  authenticated principal holding `roles.write`. (The package-level `UpdateRole` at rbac.go:903
  is a mock stub, NOT wired into the router — not the live path.)
- **Confidence:** HIGH that the code swallows the errors and returns 200 unconditionally
  (visible from code alone). The *occurrence* of a mid-loop storage failure requires fault
  injection to OBSERVE, but the swallow-and-report-success behaviour is unconditional in code.
- **Observability note:** Visible from code alone. Demonstrating the wrong end-state in a test
  requires fault injection (making `RemovePermissionFromRole`/`AssignPermissionToRole`'s storage
  write fail). Per CLAUDE.md "test a fails-open path by asserting the EFFECT, not the return
  value": asserting the HTTP status would pass before and after any fix — the only valid
  assertion reads the role's actual permission set back from storage.

---

## Finding 2 — Role permission replacement is non-atomic in BOTH transports (remove-all-then-re-add with no transaction)

- **Classification:** DEFECT (atomicity); the HTTP side escalates it to the SECURITY-DEFECT in
  Finding 1 by also hiding it.
- **Location:**
  - gRPC: `server/grpc/services/role_service.go:146-161`
  - HTTP: `server/http/handlers/rbac.go:394-404`
  - core primitives: `internal/core/rbac_management.go:131` (Assign storage write),
    `:154` (Remove storage write) — each is its own standalone storage call; neither handler
    wraps the remove+add sequence in `WithTransaction`.
- **The wrong assumption:** The doc comments (rbac_roles.go:124-127; role_service.go:145
  "A provided permission list replaces the entire set") frame "replace the set" as a single
  logical operation, but it is implemented as N independent `RemovePermissionFromRole` calls
  followed by M independent `AssignPermissionToRole` calls, each its own storage write with no
  surrounding transaction. There is a window in which the role has strictly fewer permissions
  than either the old OR the new set — and if any write fails mid-sequence the role is left
  in that reduced state permanently.
- **Concrete trigger scenario (gRPC, which DOES propagate the error):** gRPC
  `RoleService.UpdateRole` with a non-empty `permissions` list. If the first add fails after
  all removes succeeded, the handler returns `codes.Internal "failed to update role permissions"`
  (role_service.go:153/158) — but the removes are **already committed**. The role is left
  stripped of its old permissions with none of the new ones applied. The caller sees an error
  (good — unlike HTTP), but the on-disk state is corrupted and not rolled back. Even on the
  pure-success path there is a transient window where a concurrent authorization check against
  this role sees a partial set.
- **Reachability trace to a live caller:**
  - gRPC: `RoleService.UpdateRole` RPC, gated by `authorizeGlobal(..., permRolesWrite)`
    (role_service.go:109). Wired via `server/proto/pb/keyorix_grpc.pb.go`'s
    `_RoleService_UpdateRole_Handler`. Live to any `roles.write` holder.
  - HTTP: same `PUT /api/v1/roles/{id}` route as Finding 1.
- **Confidence:** HIGH (code-visible: no `WithTransaction` wraps either loop). The corrupted
  end-state after a mid-loop failure requires fault injection to OBSERVE; the transient-window
  non-atomicity is structural and present on every call.
- **Observability note:** Non-atomicity is visible from code alone. The permanent-corruption
  outcome after a mid-loop failure needs fault injection to reproduce.

---

## Finding 3 — HTTP UpdateRole discards the final permission-read error, so the "permissions" field echoed to the client may not reflect actual state

- **Classification:** DEFECT (low severity)
- **Location:** `server/http/handlers/rbac.go:371` — `perms, _ := h.coreService.Storage().GetRolePermissions(r.Context(), id)`
- **The wrong assumption:** The success response (line 372) echoes `perms` as the role's
  current permission set, but the read error is discarded. If `GetRolePermissions` fails, `perms`
  is nil/empty and the client is shown an empty permission list alongside "Role updated
  successfully" — a second way the 200 response can misrepresent the true state. Combined with
  Finding 1, the echoed `permissions` field is doubly unreliable as confirmation.
- **Reachability trace:** Same live route `PUT /api/v1/roles/{id}` (router.go:1003).
- **Confidence:** HIGH that the error is discarded (code-visible). Impact is informational
  (misleading response body), hence low severity on its own.
- **Observability note:** Visible from code alone; needs fault injection to OBSERVE a wrong echo.

---

## Cross-transport comparison (the core asymmetry)

The gRPC handler propagates storage failures from the permission loop (returns `codes.Internal`,
role_service.go:153/158); the HTTP handler does NOT (swallows remove errors entirely, logs-only
for add errors, returns 200). Both share the non-atomicity of Finding 2. So the SAME logical
operation reports failure on one transport and success on the other for an identical underlying
fault — the exact "duplicated per-transport logic that silently drifts" risk that the #1660
consolidation (rbac_roles.go:4-15) set out to eliminate, but which was only consolidated for the
role-row write (`core.UpdateRole`), NOT for the permission-replace step that still lives
inline and divergent in each handler.

## Not findings (checked and cleared)

- Built-in-role protection: `core.UpdateRole` rejects built-in roles (rbac_roles.go:129-132)
  BEFORE the permission loop in both transports, and both call it unconditionally even for
  permission-only updates — a `roles.write` holder cannot shrink admin/system_admin. Works as
  documented.
- Privilege-bundling ceiling: HTTP pre-authorizes every requested permission against the
  actor's own authority before any mutation (rbac.go:331 → authorizeAndCollectPermissions);
  gRPC does so in `resolvePermissionIDs` (role_service.go:147). The #169 "strip-then-fail"
  concern for a permission the actor lacks is correctly closed. The RESIDUAL gap is a *storage*
  failure on a permission the actor DOES hold — that is Findings 1/2, not an authz bypass.
- Role rename: no rename path exists (no Name field on either UpdateRoleRequest) — confirmed by
  the existing guard; not re-litigated.

# ADR-084: Admin permission-bypass must be a structural role property, not a name match

## Status

**Accepted.** This ADR records the decision on *what mechanism* should
replace name-based admin-role recognition. It makes **no code changes** —
implementation is deferred to its own follow-up work now that this is
accepted. Two verifications (immutability of the proposed column;
fail-closed behavior at all six call sites) were run before acceptance —
see "Verification" below. Two issues independently surfaced by that work
are filed and tracked separately (`#1496`, `#1497`), not blocking
acceptance here.

## Context

`roleSetContainsAdmin` (`internal/core/authz.go:346-364`) is the permission
bypass at the center of the RBAC system: for a resolved role-ID set, it
checks whether any ID matches one of `adminRoleNames` (`"super_admin"`,
`"admin"`, `"system_admin"`, `"project_admin"`), resolved by name via
`storage.GetRoleByName`. It has six production call sites
(`authz.go:229,247,328,379,453`, `dynamic_secrets.go:325`), gating: the
general `Authorize`/`principalHasScopedPermission` chokepoint, `IsGlobalAdmin`
(unfiltered-listing short-circuit), and three privilege-ceiling guards
(admin-role reinstatement, machine-token issuance, dynamic-secret backend
binding).

`models.Role` (`internal/storage/models/models.go:517-521`) has three
fields — `ID`, `Name` (`unique;not null`), `Description` — and no structural
marker distinguishing a seeded admin-tier role from an arbitrary
customer-created one. `Name` is otherwise an ordinary mutable column
(`UpdateRole` permits renaming any role, `CreateRole` permits any name).
This means:

1. **Renaming the seeded admin role silently drops its bypass.** Every
   `roleSetContainsAdmin`-gated check stops recognizing holders of that role
   as admins — no error, no audit event.
2. **A customer-created role acquiring one of the four reserved names
   silently gains the bypass.** Nothing reserves `"admin"`,
   `"super_admin"`, `"system_admin"`, or `"project_admin"` against reuse.

Both failure modes are silent. This is a live authorization boundary, so
this ADR is written and agreed before any implementation.

### `project_admin`'s mix with three global-conceptual names: settled, not re-litigated

`adminRoleNames` mixes `project_admin` (project-scoped by design) with three
roles whose expected assignment is global. This is **intentional and
verified correct**, recorded here so the question does not resurface:

- `authz.go:165-172`'s own comment states it: *"A global (project 0) admin
  therefore bypasses everywhere; a project-scoped admin bypasses only
  within that project."*
- The mechanism is enforced upstream of `roleSetContainsAdmin`, in
  `GetUserRoleIDsAt`'s SQL: `WHERE user_roles.project_id = 0 OR
  (user_roles.project_id = ? AND ...)`. Called with `Scope{}` (global), this
  reduces to `project_id = 0` only — a `project_admin` role held at project
  5 cannot appear in a global-scope role-ID query, by construction.
- `TestAuthorizeTwoTierScopes` (`auth_bootstrap_rbac_test.go:138`) asserts
  this empirically: a `project_admin` bypasses within its own project and is
  explicitly asserted to **not** reach another project.

Any redefinition of "admin" in this ADR must preserve this property exactly:
`project_admin` bypasses only at the scope it is held, the other three
bypass everywhere they are held (which, by seeding convention, is global).

### The unfinished half of G05

G05 (`requireEqualOrGreaterAdminAuthority`, `authz.go:466-517`) already
replaced a role-NAME comparison with a bundled-PERMISSION comparison — but
only on one side of the function. It resolves every scope the *target*
holds a role at, unions the target's bundled permissions via
`rolePermissionNameSet` (a direct `GetRolePermissions` call — no
`Authorize`, no `roleSetContainsAdmin`), then for each of those permissions
calls `c.Authorize(ctx, actorID, permName, scope)` to check the *actor* also
holds it.

Traced what `c.Authorize` does when called from inside that loop: it still
runs

```go
if c.roleSetContainsAdmin(ctx, roleIDs) {
    return true, nil
}
return c.storage.RoleSetHasPermission(ctx, roleIDs, permission)
```

So the **actor** side of G05's own ceiling check still resolves through
`roleSetContainsAdmin`'s current name-based bypass. G05 closed the blind
spot where a *target's* de-facto admin role went undetected because it was
named something other than the fixed four — but the function that replaced
the name check still depends on the name check to evaluate the other party
in the same comparison. The mutability problem `roleSetContainsAdmin` has
today is therefore still load-bearing inside the function meant to have
moved past it.

## Decision

**Add a structural, non-name column to `models.Role`: `bypasses_permission_checks bool`.**

Not `is_system`: every one of the nine seeded roles in `defaultRoles`
(`admin`, `editor`, `viewer`, `system_admin`, `system_auditor`,
`system_viewer`, `project_admin`, `project_developer`, `project_viewer`,
`project_auditor`) is "system" in the sense of being built-in/seeded —
`system_viewer` and `editor` are seeded and must **not** bypass permission
checks. A flag named for seeded-ness would be wrong for five of those nine
roles. `bypasses_permission_checks` names the actual authorization
statement being made, so it cannot be misread as a broader "is this role
special" marker.

`roleSetContainsAdmin` becomes: does any role ID in the set have
`bypasses_permission_checks = true`, resolved by ID (`GetRole`/a batch
lookup), never by name. Renaming a role does not move the flag. A
newly-created role never has the flag regardless of what it is named
(setting it is a separate, presumably-gated mutation — left to
implementation). `project_admin`'s scope-limited semantics are preserved
unchanged: the flag only says "this role's holder bypasses checks *at the
scope the role is held*" — the SQL-level scope filtering in
`GetUserRoleIDsAt` that already makes `project_admin` behave correctly is
untouched by this decision.

### Why not the other two options

**Permission-set comparison (extending G05's actor-side gap the way it
already works on the target side)** — i.e., redefine "admin" as "this role
set's bundled permissions cover \[some reference set\]," using
`rolePermissionNameSet`/`GetRolePermissions` directly (never `c.Authorize`,
which would be genuinely circular: `Authorize` → `roleSetContainsAdmin` →
(redefined) → needs `Authorize` to check permission coverage → `Authorize`
→ ...). This is **not circular** if built on the direct-lookup primitive —
`rolePermissionNameSet` proves that shape works, since it already runs with
no dependency on `Authorize` or `roleSetContainsAdmin`. But it has three
real costs this ADR does not think are worth paying:

- **Cost on every `Authorize` call, honestly.** `roleSetContainsAdmin`
  today is up to four `GetRoleByName` lookups (indexed, no join). A
  permission-set version needs `GetRolePermissions` (a
  `permissions`-`role_permissions` join) for every role ID in the caller's
  set, then a comparison against the reference set. Checked for an existing
  cache that would absorb this: none exists — `RoleSetHasPermission` and
  `GetRolePermissions` are both plain, uncached SQL queries, and `Authorize`
  is the hottest path in the system (nearly every authenticated request).
  This is real, recurring cost on every permission check, not a one-time
  migration cost.
- **It needs its own reference set, which reopens the exact problem it's
  meant to close.** G05's version compares actor-vs-target — a *relative*
  comparison with no fixed "admin" definition to maintain. `roleSetContainsAdmin`
  needs an *absolute* one: "holds \[what\], exactly, to count as admin?"
  Checked whether "every currently-defined permission" could serve as that
  set (see the ADR-044 investigation below) — it can't be trusted as a live
  invariant, only as a today-coincidental match between two independently
  hand-maintained lists. A curated subset avoids that specific problem but
  is itself a new hand-maintained list — no better than `adminRoleNames`
  for the mutability question this ADR exists to close, since nothing
  prevents *it* from drifting either.
- **A genuine consistency gap during the exact window ADR-044 exists to
  bridge.** ADR-044's reconcile adds a newly-introduced permission to an
  upgraded install's baseline roles at the next boot, but it is best-effort
  and non-blocking (see below) — there is a real window, on any given
  upgrade, where a new permission exists in the catalog but has not yet
  been granted to `admin`/`system_admin`. A permission-set-based "admin"
  definition would make the admin roles' own bypass status wobble during
  that window; today's name match does not have this failure mode at all.

**Investigate whether the bypass is redundant for install-admin roles
(ADR-044 reconcile)** — ruled out, verified against code rather than
assumed:

- `ReconcileRBACPermissions` (`internal/core/rbac_reconcile.go`) only grants
  a permission to a role's baseline set when that permission was **created
  in the same reconcile run** — `id, isNew := created[permName]; if !isNew
  || held[permName] { continue }`. It never repairs a missing grant of a
  permission that already exists in the catalog. ADR-044's own text confirms
  this is deliberate: *"Permissions that already exist are never touched...
  This is the load-bearing safety property"* (preserving operator
  customizations). Reconcile therefore provides **no ongoing guarantee**
  that `admin`/`system_admin` hold every canonical permission — only a
  one-time top-up for permissions genuinely new to the catalog. Filed as
  its own issue, independent of this ADR: `#1496` (reconcile is
  additive-on-create only, not convergent — flags that ADR-082 branch 4's
  upgrade story for `connect.platform.use` depended on the case that holds
  today, newly-created permissions, and that reasoning should not be
  reused for a future permission addition without checking which case it's
  in).
- Compared `adminPermissions` (`auth_bootstrap.go:95-101`, 14 entries)
  against `defaultPermissions` (`auth_bootstrap.go:47-92`, 14 entries)
  directly: they match exactly, today. But this is coincidental
  hand-maintenance, not enforced — grepped every test file in
  `internal/core`: zero tests assert `adminPermissions` stays a superset of
  (or equal to) `defaultPermissions`. Reconcile's own grant step is driven
  by `defaultRoles`' static `rdef.Permissions` list (i.e.
  `adminPermissions` for the admin roles) — a permission added to
  `defaultPermissions` without a matching addition to `adminPermissions`
  would be created in the catalog but never granted to admin, and reconcile
  has no mechanism to catch that omission; it isn't reconciling against
  `defaultPermissions`, it's reconciling `admin`'s grants against `admin`'s
  own declared list. Filed as its own issue: `#1497` (a small table test
  asserting the two lists agree, so a future divergence fails CI instead
  of shipping silently).
- Reconcile runs synchronously, once, in `initializeCoreService`, before
  any listener starts serving requests — no live authorization decision
  races an in-progress reconcile. But it is explicitly best-effort: a
  failure (e.g. a transient write error) is only logged
  (`"RBAC permission reconciliation: %v (continuing)"`), never retried,
  never blocks boot, with no operator-visible signal beyond that log line.
- **Verdict: reconcile is not reliable enough to depend on for an
  authorization decision.** Even the narrow guarantee it does provide
  (top-up newly-catalogued permissions) can silently fail to apply on any
  given boot. The bypass is not provably redundant for install-admin roles —
  today's match between the two lists is a coincidence of manual
  maintenance, not an enforced invariant, so the problem does **not**
  shrink to `project_admin` alone. All four names stay in scope for the
  structural-flag decision above.

### Both name lists collapse into one concept

`adminRoleNames` (4 names, `authz.go:173`) and `installAdminRoleNames` (3
names, `rbac_management.go:407` — the same three global-conceptual roles,
`project_admin` excluded) are separately maintained today and can drift
independently of the mutability issue this ADR addresses — two hand-written
lists that happen to overlap on three of four names, with no test tying
them together.

`installAdminRoleNames`' own doc comment says what it actually means: *"the
roles that confer install-wide administration **when held at the global
scope**"* — this is not a semantically distinct set of roles, it is the
same bypass property, filtered by the scope the role happens to be *held*
at. Under the structural flag, `project_admin` held at the global scope
would bypass everywhere too (the existing SQL-scope mechanism already
guarantees this identically to how `system_admin` behaves globally) — so
excluding it from `installAdminRoleIDSet` today is really "nobody is
expected to assign `project_admin` globally," not "it is a lesser bypass."

**One flag, one query shape.** `installAdminRoleIDSet` should stop being a
second hand-maintained name list and become a scope-aware query over the
same flag — "which flagged roles does this principal hold *at `Scope{}`*" —
the same shape `IsGlobalAdmin` already uses via `scopedRoleIDs(ctx, userID,
Scope{})`. This is a genuine simplification the flag enables, not a new
requirement; whether `installAdminRoleIDSet`'s current project_admin
exclusion should be revisited is a separate, smaller question left to
implementation, not decided here.

### Migration

Existing installs acquire the flag via a **one-time name match at
migration**: for each of the current four `adminRoleNames`, if a role with
that exact name exists, set `bypasses_permission_checks = true` on it. This
is explicitly a **snapshot of today's state**, not an ongoing decision — it
runs once, at the moment the migration applies, using the same name list
this ADR is retiring as an *ongoing* mechanism. After migration, the flag
is authoritative: a rename does not move it, and no future role can acquire
it by matching a name. The one-time use of name-matching here is a
deliberate, bounded exception to the ADR's own conclusion, not a
contradiction of it — the risk this ADR closes is a name match evaluated
repeatedly, forever, against a value that can change; a single migration-
time snapshot is the mechanism, not the problem.

## Out of scope, recorded

Two other name-based lookups surfaced during investigation, deliberately
left untouched by this decision:

- **`break_glass.go:106`**, resolving the config-supplied `EmergencyRole` by
  name. Same initial mutability exposure (a renamed/reassigned role name
  resolves differently), but the consequence differs meaningfully: it fails
  **closed** on lookup error (unlike `roleSetContainsAdmin`'s silent
  `continue` when a name isn't seeded), and it applies two further
  permission-*content* checks after resolution — refusing a role that is
  itself install-admin, and refusing one that holds `roles.assign`. A
  renamed-and-reassigned role would still need to pass both of those
  checks to be dangerous; name-matching alone is not sufficient there the
  way it is for `roleSetContainsAdmin`.
- **`scim.go:194`, `users.go:174`**, both hardcoding
  `GetRoleByName(ctx, "system_viewer")` to auto-assign a minimal baseline
  role to new users, explicitly best-effort. On lookup failure they silently
  assign no role at all — the failure direction is *under*-privileged, not
  a bypass. Not the same risk shape as the roles this ADR addresses.

## Verification

Two checks were run, read-only, before accepting this ADR.

### 1. Immutability: what stops `bypasses_permission_checks` being set post-migration?

Both GORM write paths `models.Role` goes through write the **entire passed
struct**, not a whitelisted subset: `LocalStorage.CreateRole` calls
`db.Create(role)`, `LocalStorage.UpdateRole` calls `db.Save(role)`. Neither
the storage layer nor GORM itself provides any column-level protection —
whatever is set on the Go struct persists. Safety today is entirely a
property of what *callers* put into that struct, not of any structural
guarantee. Traced every write path:

- **`RBACHandler.UpdateRole`** (`server/http/handlers/rbac.go:289`): decodes
  the request into a separate `UpdateRoleRequest` DTO, fetches `role` fresh
  via `GetRole(id)`, and copies across only `role.Description` before
  `.Save()`. A hypothetical `BypassesPermissionChecks` field on `models.Role`
  would carry through unchanged from the DB fetch — safe, but only because
  the handler happens to copy one named field, not because anything stops
  it from copying more.
- **`RoleGRPCService.UpdateRole`** (`server/grpc/services/role_service.go:102`):
  identical shape — `GetRoleWithPermissions` fetches fresh, only
  `role.Description` is set from the protobuf request before `.Save()`.
- **`RBACHandler.CreateRole`** (`server/http/handlers/rbac.go:132`): builds
  a fresh `&models.Role{Name: req.Name, Description: req.Description}`
  literal — any unlisted field, including a new column, is Go's zero value
  (`false` for a bool). Safe by construction.
- **`/system` proxy routes**: no route registered under `/system` touches
  `models.Role`'s own columns today (checked every `Post`/`Put`/`Patch`/
  `Delete` registration in `router.go`). The RBAC-shaped proxy routes there
  (`/system/rbac/assign-role-with-expiry`, `/system/machine-identities/{id}/
  roles/{roleId}`, etc.) all write to *assignment* tables (`user_roles`/
  `group_roles`), never to `Role` itself. But `/system` is demonstrably not
  read-only for authorization-adjacent state: `CreateConnectorProjectBindingProxy`
  (`server/http/handlers/connector_project_bindings_proxy.go:102`, `#1477`)
  already writes a fresh row into `ConnectorProjectBinding` — a table that
  feeds `core.ConnectOwnership` (an authorization input) — via exactly the
  same safe pattern: a narrow wire DTO (`connectorProjectBindingCreateBody`,
  3 fields) decoded into an explicit struct literal, never a raw model
  passthrough. This is real precedent that a future `/system` proxy for
  `Role` is plausible, not hypothetical — and that the established,
  currently-safe convention for building one is exactly the pattern above.
- **SCIM** (`internal/core/scim.go`): never constructs or writes a
  `models.Role` — its only `Role`-adjacent call is the `GetRoleByName`
  lookup for the `system_viewer` best-effort assignment (out of scope,
  above).

**Conclusion: every current write path is safe, but only by convention, not
by structure.** `db.Save`/`db.Create`'s full-struct-write semantics mean
nothing stops a *future* handler — including a future `/system` proxy,
which `#1477` establishes as a real category of route — from decoding a
wider request shape and copying an extra field across, the same way
`.Description` is copied today. **Implementation must not treat "no
handler exposes it today" as sufficient.** The mutation path for
`bypasses_permission_checks` must be a dedicated, narrow function (not
`UpdateRole`'s general path), and ideally not reachable through the general
role-management API at all — this is recorded as a requirement in
Consequences below, not resolved here.

### 2. Fail-closed: is the zero value safe at all six call sites?

**Not uniformly** — this needed to be checked per site, not assumed, and
the answer has a real asymmetry that must carry into implementation.

`roleSetContainsAdmin` today has no error return at all: any
`GetRoleByName` failure — including a genuine transient storage error, not
just "this deployment never seeded that role" — is silently swallowed
(`continue`) and indistinguishable from a true "not admin" result. Traced
what that means at each site:

| Site | On `roleSetContainsAdmin` returning `false` (correctly, or via a swallowed resolution error) |
|---|---|
| `authz.go:229` `Authorize` | Falls through to a real `RoleSetHasPermission` check — no bypass, correctly evaluated. **Safe.** |
| `authz.go:247` `principalHasScopedPermission` | Same shape. **Safe.** |
| `authz.go:328` `IsGlobalAdmin` | Caller falls back to scope-filtered (subset) listing. **Safe** (worst case: an actual admin sees a filtered view). |
| `authz.go:379` `requireGlobalAdminToReinstateAdminRoles` | `if !containsAdmin { return nil }` — **skips the ceiling check and allows the reinstatement.** If the roleIDs *being reinstated* truly contain an admin-tier role but resolution silently failed, this wrongly permits resurrecting an admin-conferring grant without verifying the actor is a global admin. **Unsafe direction.** |
| `authz.go:453` `requireMachinePrivilegeCeiling` | Same shape as 379 — `false` skips the ceiling check and allows machine-token issuance without verifying actor authority. **Unsafe direction.** |
| `dynamic_secrets.go:325` `requireDynamicSecretAdminAuthority` | `if !containsAdmin { return error }` — denies the bind. **Safe** (worst case: a legitimate project_admin is wrongly refused). |

Sites `379` and `453` ask a different question than the other four — not
"does the caller get a bypass" but "does *this role set* (the one being
reinstated, or a machine's full role list) contain an admin-tier role, so
the ceiling check should fire" — and for that question, a false negative
from a swallowed resolution error is the dangerous direction, not the safe
one. **This is a property of the current name-based implementation
already**, not something the structural-flag redesign introduces — traced
`GetRoleByName`'s two error branches (`ErrorRoleNotFound` and
`ErrorRetrievalFailed`) and confirmed `roleSetContainsAdmin`'s `continue`
does not distinguish them today.

This does not change the recommendation — a structural flag is no less
safe on this axis than the current name lookup, and is strictly better on
the two failure modes this ADR exists to close. But **implementation must
not carry the current silent-`continue` pattern forward unexamined at
sites 379 and 453.** The redefined resolution should surface a genuine
storage error to those two callers (e.g. `roleSetContainsAdmin` returning
`(bool, error)`, with 379/453 treating a non-nil error as "assume the set
may contain an admin role" — fail toward requiring the ceiling check, not
away from it) rather than silently defaulting to "no admin role found" the
way today's implementation does for all six sites uniformly. Left to
implementation; not itself filed as a separate issue since it is
implementation guidance for this ADR's own follow-up, not an independent
defect.

## Consequences

- `roleSetContainsAdmin`'s six call sites change from up to four
  `GetRoleByName` calls to an ID-based lookup of the resolved role set's
  flag — no behavior change at any of them beyond closing the two silent
  failure modes described above.
- `Role`'s mutation surface (`CreateRole`/`UpdateRole`) needs a decision, in
  implementation, about who may set or clear `bypasses_permission_checks`
  and through what path — almost certainly not the general role-management
  API, to avoid reopening the "customer role acquires the property" failure
  mode through a different door. Not decided here.
- `installAdminRoleIDSet` can be simplified to a scope-aware flag query,
  removing one of the two hand-maintained name lists entirely.
- Implementation is its own follow-up: schema migration, the flag-setting
  policy, `roleSetContainsAdmin`'s rewrite, and `installAdminRoleIDSet`'s
  simplification, each independently testable against the existing
  `TestAuthorizeTwoTierScopes`-style scope assertions plus new tests for
  the two failure modes this ADR closes (rename drops bypass; name reuse
  gains it).

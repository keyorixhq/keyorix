# ADR-082: Keyorix Connect connector tenant (project) scoping

## Status

**Accepted.** Investigation and three rounds of revision complete (see
`REMEDIATION-STATUS.md` for the full round-by-round history). This ADR
remains scoped to the design decision only — see "Out of scope" below for
what is deliberately deferred to implementation-phase follow-up work.

### Implementation plan (recorded here; not started)

Four separate branches, one logical change each:

1. Config schema (`scope`, `project`, `environment`, `connect.allow_unscoped`)
   and boot validation (C).
2. Ownership enforcement (E) and `ListConnectors` filtering.
3. Audit changes (H) — the three-way decision reason, the switch to
   `writeAuditEventFull`, `AuditEvent.ProjectID` population.
4. The new `connect.platform.use` permission (B) and its addition to
   `adminPermissions`.

**No branch has been started as of this ADR's acceptance.**

## Context

Keyorix Connect (ADR-043) proxies authorized, audited read-through access to
external secret stores. Authorization today is exactly three controls:

1. **`connect.read`** (ADR-044) — a single **global** permission. A caller
   either may use Connect at all, or may not. There is no project-scoped
   variant.
2. **`ConnectRefGrant`** (ADR-045) — an opt-in, deny-once-present
   `(role, connector, ref_prefix)` allowlist. ADR-045 states explicitly (its
   own text, line 57): "since Connect is a global surface" — the
   per-reference grant was designed against the same global-only assumption
   this ADR now revises (see (I) below — the amendment is explicit, not
   silent).
3. The operator-configured, per-connector `allowed_refs` prefix allowlist —
   uniform, applies identically to every caller.

**The gap:** none of these answer "which Keyorix project owns this
connector, and is the caller a member of it?" A user holding global
`connect.read` — or a role with a connector-wide empty-prefix
`ConnectRefGrant`, ADR-045's own documented pattern for preserving admin
access — can read through **any** configured connector regardless of which
team's/project's external store it actually is. `connect-findings.json#2`
(info severity) flagged this as "architectural... flagging for product
confirmation," not a coded defect — this ADR is that confirmation.

### Blocking question, resolved before drafting: are role assignments project-scoped?

**Yes.** Verified directly against the schema, not assumed:

```go
type UserRole struct {
    UserID        uint `gorm:"primaryKey"`
    RoleID        uint `gorm:"primaryKey"`
    ProjectID     uint `gorm:"primaryKey;not null;default:0"` // 0 = global sentinel
    EnvironmentID uint `gorm:"primaryKey;not null;default:0"`
    ExpiresAt     *time.Time `gorm:"index"`
}
```

A user can hold multiple `UserRole` rows simultaneously — one at the global
scope (`ProjectID = 0`) and/or several at distinct project scopes. This is
the same composite-key, zero-sentinel convention used throughout RBAC
(`UserGroup.ProjectID`, `GroupRole.ProjectID`, etc.), already established
before this ADR.

**The caller's authorized project set is derivable server-side, with no new
request parameter**, via primitives that already exist and are already
proven in production authorization paths:

- `storage.GetUserRoleScopes(ctx, userID) ([]Scope, error)` — "returns the
  distinct (project, environment) scopes at which userID holds ANY role,
  directly or via a live (non-deleted) group" (its own doc comment,
  `internal/core/storage/interface.go:998`). Already the scope-discovery
  step behind the impersonation admin-rank-ceiling check (#165).
- `storage.GetMachineRoleScopes(ctx, machineID) ([]Scope, error)` — its
  machine-identity mirror (G33 parity fix), same shape.
- `core.GetReadableScopes(ctx, principalID, permission)`
  (`internal/core/authz.go:768`) composes these two with an
  actor-type dispatch (`actorTypeFromContext`) and a per-scope permission
  filter, already used by `ListSecrets` for exactly this "what can this
  caller reach without an explicit filter" question, including PAT-scope
  narrowing and fail-closed-on-error behavior.

For Connect's ownership check specifically, "project membership" means
holding *any* role at that project's scope — not specifically `connect.read`
scoped to it (which never happens; `connect.read` stays global-only, see
(D)). This is `GetUserRoleScopes`/`GetMachineRoleScopes`'s raw, unfiltered
output, not `GetReadableScopes`'s permission-filtered output — a
distinction worth being precise about since the two primitives look similar
but answer different questions. The raw output is not narrowed to
`ProjectID != 0` before use: a `{ProjectID: 0}` (global) entry is
deliberately retained and given specific meaning by (E)'s admin-scope-set
expansion, not discarded as noise.

**This settles the design**: no caller-supplied project ID, no new field on
either read-path transport. See (D).

### Investigation findings (unchanged from the prior pass, verified directly)

**Every call site checking `connect.read`** — four total, all global, none
project-scoped: HTTP `GET /connect/connectors` (`router.go:424`), HTTP
`GET /connect/{name}/secret` (`router.go:425`), gRPC `ListConnectors`
(`connect_service.go:36`), gRPC `ReadSecret` (`connect_service.go:48`). Not
exposed via CLI or MCP. `ReadFederatedSecret`
(`internal/core/connect.go:56`) — the only call site of
`connectManager.Get` anywhere in the tree — has signature
`(ctx, actorType, principalID, connectorName, ref)`.

**`ConnectRefGrant` has no `ProjectID`; `Connector` is a bare string, not a
foreign key** — matched against `connect.Manager`'s in-memory map key.
Expiry checked directly at read time (`ExpiresAt *time.Time`, nil =
permanent), no background sweep needed, mirroring
`UserRole.ExpiresAt`/`ShareRecord.ExpiresAt`. Federated reads are audited
via `writeAuditEvent` — the short form that hardcodes `projectID = nil` into
`writeAuditEventFull`. `AuditEvent.ProjectID *uint` already exists as a
column; Connect simply never populates it today.

**There is no "create a connector" API — connectors are pure server
config, not a database entity**, and this ADR keeps it that way (see (A)).
`server/main.go:563-604` reads `cfg.Connect.Connectors` (YAML) once at boot
and builds `connect.Connector` instances held in an in-memory `Manager`
(`internal/connect/connect.go`). The `Connector` interface is
`Name() / Type() / GetSecret()` — no scope field, no persistence, no
runtime CRUD, no numeric ID.

**The GCP-connector `ProjectID` naming collision**: the existing
`gcp-secret-manager` connector config type already has a `ProjectID` field
(`server/main.go:570-574`) — but that is a **GCP** project ID (an
ambient-cloud-identity scope string, #431), unrelated to Keyorix's own
`Project` entity. An unset GCP `project_id` today produces only a
boot-time `log.Printf` warning, not enforcement. **These two `ProjectID`
concepts are unrelated and must not share a config field name.** Fixing the
GCP one's boot-warning-only enforcement gap is out of scope for this ADR
(see "Out of scope").

## Decision

### A. Ownership is declared in connector YAML config. No DB table, no DB mirror.

Connectors remain pure server configuration, exactly as today. Each
connector config entry gains a required `scope` field (see (B)) and an
optional `project` reference — a Keyorix project's **name**, not a numeric
ID (see the subsection immediately below for why).

**Explicitly decided: no DB table mirrors connector metadata.** There is no
runtime connector-management API today (creating/updating a connector
requires a config change and restart, unchanged by this ADR), so a DB row
would exist solely to be read back at authorization time — pure overhead
with no capability it unlocks. `ConnectRefGrant` continues to reference
connectors by the same bare name string it already uses; nothing about this
ADR requires a stable numeric connector ID. **Revisit only if/when runtime
connector CRUD ships** — that is the point at which a DB-backed identity
would earn its keep, not before.

#### A.1 Project names are mutable and freed on soft-delete — why `project:` pins by ID, once, and a rename is a deliberate boot failure

Verified directly against the schema and the update path, not assumed:
`Project.Name` (`models.go:9-17`) carries no immutability — `UpdateProject`
(`catalog.go:120,132`) directly reassigns `project.Name = name` with no
restriction — and its own doc comment states explicitly that uniqueness is
enforced by a **partial** index, `LOWER(name) WHERE deleted_at IS NULL`,
"so a soft-deleted project's name is still freed for reuse." Both facts
combine into a real risk: if a connector's ownership were re-resolved by
name on every boot, an ordinary project rename — or a delete-and-recreate
under the same name, by a different admin, for an unrelated reason — would
silently reassign which project owns a connector, with no config change and
no operator awareness that Connect was affected at all.

**The fix: `project:` names the project by string, but is resolved to a
numeric project ID exactly ONCE — at the first boot after a connector is
configured — and pinned via a new persisted row,
`ConnectorProjectBinding` (`connector`, `project_id`, `project_name`).
Every later boot resolves by the STORED ID, never by re-reading the config's
`project:` name against live `Project` rows.** If the bound project's
CURRENT name (looked up by the stored ID) no longer matches the name
recorded in the binding at first-boot time, boot fails, naming both the
stored and current name — this is a **deliberate** boot failure, not a
silent reassignment: a rename that happened between boots is exactly the
ambiguous case (intentional relabeling vs. an unrelated project stealing the
name) this ADR refuses to resolve automatically. The same applies if the
bound project no longer exists (deleted). There is no operator-facing
binding-management surface in this branch (out of scope, see below); the
remediation path today is to remove the stale `connector_project_bindings`
row (a direct DB action) once the rename is confirmed intentional, then
restart — a real if unpolished escape hatch, not a dead end.

This mirrors, at a smaller scale, the same "explicit value required,
absence/ambiguity denies" shape (C) already establishes for `scope` itself
— a `project:` name is a human-friendly config-time label, not a security
identifier; the security identifier is the persisted numeric ID it resolves
to once, not the string re-derived from it on every boot.

### B. `scope: project | platform` — exactly two values, no third state

**`platform` is the expected case for shared infrastructure, not an
exception to `project`.** A connector backing genuinely org-wide
infrastructure — a central IdP-backed store, an org KMS/HSM, an SMTP-relay
credential set — is normal, common Connect usage, not a rare carve-out;
Infisical's org-level "app connections," reused across every project in the
org by design, is the closest external analogue. `scope: project` is the
**deliberate narrowing** of a connector to exactly one team/project's
boundary, chosen when a connector's backend genuinely should not be
reachable outside one project — the exception case, not the default one.
Neither value is privileged in the config schema or the authorization order
below; this is a framing correction for how operators should think about
choosing between them, not a change to (C)'s boot-fail-on-missing-scope
requirement, which applies identically to both values.

- **`project`** — the connector belongs to exactly one Keyorix project.
  Requires `project:` in the same config entry (a config-load-time error,
  not a runtime one, if `scope: project` is set with no `project:` key).
  Authorized for callers who are members of that project (see (E)) or hold
  a matching `ConnectRefGrant` (see (F)).
- **`platform`** — org-wide connectors, reachable by any caller who holds
  the new permission, **`connect.platform.use`**, on top of `connect.read`
  — holding `connect.read` alone is not sufficient for a
  `platform`-scoped connector.

There is no `legacy_unscoped` value and no phased default-flip release (a
real revision from the prior draft of this ADR, per direct instruction).
Instead:

### C. Missing `scope` fails boot; the only escape hatch is explicit and per-deployment, not per-connector

A connector config entry with no `scope` key **fails server boot**, with an
error naming every offending connector by its config-file name (not just
the first one found — an operator fixing config should not have to
restart-and-discover connectors one at a time).

The only way to boot anyway is a single, explicit, deployment-wide config
flag: `connect.allow_unscoped: true`. When set, boot proceeds, but **every**
connector missing a `scope` emits a `WARN`-level log line naming it, at
every boot, for as long as the flag stays set. There is no per-connector
opt-out and no silent variant — `connect.allow_unscoped` unset (the
default) means absence of `scope` is a hard failure, full stop. This is the
same "explicit value required, absence denies" shape already established in
this codebase (most recently ADR-076's `POD_NAMESPACE` hard-fail-on-empty),
simplified here to a single boot-time gate rather than a phased migration
because — unlike ADR-076's operator RBAC default, which had to preserve a
*running* cluster's existing behavior across an upgrade — Connect connector
config is edited and the server restarted as one atomic operator action;
there is no live-traffic window a phased flip would need to protect.

### D. Ownership is derived server-side from role assignments. No new request parameter, no proto change, no signature change.

Per the blocking-question resolution above, `ReadFederatedSecret`'s
signature (`ctx, actorType, principalID, connectorName, ref`) is
**unchanged**. No new HTTP query parameter, no new field on
`ReadFederatedSecretRequest` (gRPC), no caller-supplied project ID
anywhere in the request path.

**A caller-supplied project ID was explicitly considered and rejected as a
hint, not a boundary.** A value the client sends is not authoritative for a
security decision it could lie about (a caller free to omit or set any
project ID would trivially bypass ownership by simply asserting the right
one) — the server must derive the caller's real project membership from
role-assignment storage, not trust a client-asserted parameter, exactly the
distrust-caller-controlled-values principle already applied throughout this
codebase's authorization layer (e.g. `refMatches`'s traversal-segment
rejection, `actorRoleIDs`'s server-side role resolution rather than a
client-asserted role list).

**Why `GetUserRoleScopes`/`GetMachineRoleScopes` (via `GetReadableScopes`'s
existing pattern), not a new scope-derivation query written for Connect.**
These primitives were chosen specifically because they already correctly
handle three cases a from-scratch query written inline at the Connect layer
would have to re-solve independently and could easily get wrong the first
time: **group-derived roles** (a user's project membership can come from a
group grant, not just a direct `UserRole` row — `GetUserRoleScopes`'s own
doc comment: "directly or via a live (non-deleted) group"), **machine
identities** (a distinct code path with no group concept, already
correctly split out as `GetMachineRoleScopes`, the G33 parity fix for a
class of bug — "helper written for humans, never updated for machines" —
this codebase has hit more than once), and **PAT narrowing** (a personal
access token restricted to fewer projects than its owner must not regain
its owner's full scope through a new, separately-written check —
`GetReadableScopes`'s own doc comment: "PAT restrictions are honoured").
Writing a new derivation for Connect risks reintroducing any one of these
three already-fixed gaps independently; reusing the existing primitive
means Connect's ownership check inherits the fixes for free and stays
consistent with every other caller of the same primitive if any of the
three is revisited again later.

**Constructing the caller's ownership scope set: `GetUserRoleScopes`/
`GetMachineRoleScopes`'s raw output, not `GetReadableScopes`'s filtered
output — and why that distinction now matters for global-scoped roles
generally, not only admin-named ones.** Ownership
derivation intentionally does not call `GetReadableScopes`, which strips
any `{ProjectID: 0}` entry before returning ("Global scope handled by
caller; skip," `authz.go:784`) and additionally re-checks a specific
permission at each scope — the wrong question for ownership, which asks
"which project is this," not "does the caller hold permission X there."
Ownership calls the raw scope-enumeration primitives directly, and that raw
output **includes** any `{ProjectID: 0, EnvironmentID: 0}` entry the caller
holds. (E) below defines what that entry means for the ownership
comparison.

### E. Authorization order: `connect.read` → ownership → `ConnectRefGrant` delegation → deny

**Revised again, on verification: the wildcard trigger is the SCOPE of a
role grant, not the role's name.** The prior draft of this section keyed
the ownership wildcard off `adminRoleNames` (resolving the caller's role
IDs at the `{0,0}` scope and checking them against the same four
admin-named strings the permission-check bypass uses). Verified before
finalizing, this ADR does not use that shape:

**`roleSetContainsAdmin` (`authz.go:346-364`) is name-based, not
structural — a real, pre-existing fragility, not introduced by this ADR.**
It resolves each of the four `adminRoleNames` strings to a role ID via
`storage.GetRoleByName`, then checks membership in the caller's resolved
role-ID set — a pure name lookup. `Role` (`models.go:517-521`) carries no
`IsSystem`/`IsGlobal`/immutable flag at all; the only thing distinguishing
a seeded admin role from any other is its `Name` column, which is mutable
and only unique, not otherwise protected. A customer role literally named
`admin` — reachable today if an operator frees that name by renaming the
seeded role, or in a deployment with a customized RBAC catalog — would
receive the same permission-check bypass the seeded `admin` role gets;
renaming the seeded `admin` role away from that string silently drops its
bypass on the next check. **This ADR does not fix `roleSetContainsAdmin`
itself** — that is a separate, standalone issue with its own blast radius
(it affects the ordinary permission-check bypass everywhere, not only
Connect) and needs its own fix on its own branch, not a rider here (see
"Out of scope"). What this ADR does is avoid inheriting that shape for the
ownership wildcard.

**The chosen trigger is structural: the scope a role is granted at
(`UserRole.ProjectID == 0`, or `MachineIdentityRole`'s equivalent), not the
role's name, and not a new permission or flag.** Two candidate rules give
different answers for a global-scoped role that is *not* admin-named: (1)
"a role held at the global scope resolves to ownership of every project,
regardless of the role's name" — matching this codebase's own existing
behavior for ordinary permission checks (next paragraph); or (2) "only an
admin-*named* role held at global scope gets the wildcard." **This ADR
adopts rule (1) explicitly, as the Decision — not (2).** A caller holding,
say, a custom `billing-viewer` role granted at the global scope, with
`connect.read` attached to it, is authorized for every `scope: project`
connector's ownership, the same as `admin`/`system_admin` — because it is
the *scope* of the grant, not the role's identity, that the wildcard keys
off. This is a deliberate, stated consequence of rule (1), not an
oversight (see Consequences).

Two things motivate rule (1). First, competitively: Doppler, Infisical,
and Kubernetes all grant an org/cluster admin implicit access to every
project/namespace by default; only HashiCorp Vault enforces strict
per-namespace isolation for its own admin tier, and Vault's operational
strictness is the exact friction Keyorix is positioned against — in
practice this mainly matters for `admin`/`system_admin`, the only roles
seeded with `connect.read` today. Second, and more concretely: this
codebase's own `scopedRoleIDs` (`authz.go:333-343`) already unions a
caller's global-scoped roles into **every** project-scoped permission
check, **for any role, not only admin-named ones** — verified directly:
`TestGetUserRoleIDsAt_ScopeBoundary` (`local_rbac_scope_test.go:60`) shows
a role granted at `ProjectID: 0` returned when querying scope `(5, 0)`
alongside that project's own grants, and the test's role `10` is not one
of the four admin-named roles — the union doesn't check the name. Rule (1)
is not a new privilege invented for Connect; it is Connect's ownership
check catching up to a scope-union rule every *other* permission-gated
action in Keyorix already follows, for any global-scoped role.

**Mechanism: retain the `{0,0}` entry, no role lookup.** The raw scope
list from `GetUserRoleScopes`/`GetMachineRoleScopes` (D) is no longer
filtered down to `ProjectID != 0` entries the way the prior draft's
implementation kept it — a `{ProjectID: 0, EnvironmentID: 0}` entry
surviving in that list *is itself* the wildcard signal; nothing further is
resolved or looked up (no `GetRoleByName`, no `adminRoleNames`
comparison). The ownership comparison — "does the caller's scope set
contain this connector's owning project, OR does it contain a `{0,0}`
entry?" — is the exact same function every caller's ownership check runs
through: a wildcard entry in the input set, not a different code path, and
not a name check. This mirrors Kubernetes' `system:masters` group: not a
hardcoded authorizer bypass, bound to the built-in wildcard
`cluster-admin` `ClusterRole` (`resources: ["*"]`), evaluated by the
*same* RBAC rule-matching code — a bypass makes the access invisible at
the point of decision, whereas a wildcard entry inside the same comparison
keeps it fully inside the auditable framework.

**Composition with PAT narrowing and machine-identity scope: verified
structurally safe, no additional intersection logic needed — the reason is
specific, not assumed.** `connect.read` itself is checked at the **global**
scope (`authorizeGlobal` → `authorizeScoped(ctx, cs, actor, perm,
core.Scope{})`, `conversions.go:184-186` — literally `Scope{0,0}`), and
`PATRestriction.Allows` (`authz.go:85-112`) denies any project- or
environment-restricted PAT at a global-scope check outright
(`r.ProjectID != 0 && scope.ProjectID != r.ProjectID` evaluates to deny
when `scope.ProjectID == 0` and the PAT's own `ProjectID` is non-zero).
**A project- or environment-narrowed PAT therefore never clears the
`connect.read` gate at all** — it never reaches the ownership check this
section defines, wildcard or otherwise. Only an *unrestricted* PAT (nil
restriction, or a restriction with `ProjectID == 0` and no narrowing
`Permissions` list — "inherit the owner's full set") can reach Connect,
and for such a PAT `PATRestriction.Allows` returns `true` unconditionally,
so it correctly inherits whatever the owning user's real ownership scope
is — project membership or the global wildcard — with no separate
narrowing step required. **This is a pre-existing consequence of
`connect.read`'s own global-only scope, not something this ADR adds or
must separately enforce** — if `connect.read` itself is ever made
project-scoped in a future ADR, this composition needs re-examination at
that time; out of scope here. **Machine identities** compose correctly for
a structurally different reason: there is no PAT-style restriction layer
for machine identities at all, so a machine identity's reach is bounded
purely by its actual `MachineIdentityRole` grants. A machine identity
holding an admin-equivalent role at a *specific* project's scope produces
a `{ProjectID, 0}` entry from `GetMachineRoleScopes`, not `{0,0}` — the
wildcard does not fire, and the identity is correctly bounded to that one
project, by construction, no additional logic needed. Only a machine
identity actually granted a role at the true global scope (`{0,0}`)
receives the wildcard — the same, pre-existing exposure
`roleSetContainsAdmin` already carries for a machine identity holding an
admin-*named* role globally (unaffected by this ADR either way), now
extended consistently to Connect ownership specifically.

```
connect.read granted?                                    → no:  deny
connector.scope == platform?
  → yes: connect.platform.use granted?  → yes: allow (reason: capability)  → no: fall through to delegation check below
connector.scope == project?
  → caller's RAW scope set (GetUserRoleScopes/GetMachineRoleScopes,
    including any {0,0} entry) contains connector.project?
                                                          → yes: allow (reason: project_membership)
  → caller's scope set contains a {0,0} entry (global-scoped
    role grant, any role name — see above)?
                                                          → yes: allow (reason: global_scope)
matching ConnectRefGrant for one of the caller's roles?  → yes: allow (reason: delegation)
                                                          → else: deny
```

- **`ListConnectors` filters**: unchanged in shape from the prior draft —
  the returned list contains only connectors the caller can reach under
  this order, evaluated with the same per-connector ownership comparison
  above. For a caller whose scope set carries the `{0,0}` global-scope
  entry, every `scope: project` connector's ownership comparison resolves
  true, so every connector appears — this falls out of the loop running the
  same comparison for every connector and every caller; there is no
  separate "if admin, return all" branch in `ListConnectors` itself.
- **`ReadSecret`/`GetSecret` denies**: unchanged — a single named connector
  + ref either is or is not authorized under the same order above; there is
  nothing to filter.
- **The permission-check bypass and the ownership wildcard are two
  independent mechanisms with two different triggers, not the same
  predicate reused twice.** `roleSetContainsAdmin` (`authz.go:346-364`,
  still short-circuiting only `connect.read`/`connect.platform.use`) is
  name-based, resolving `adminRoleNames` via `GetRoleByName`. The ownership
  wildcard defined above is scope-based (does the raw scope set contain
  `{0,0}`, full stop) and never calls `GetRoleByName` or compares against
  `adminRoleNames`. A role held at the global scope that is **not** one of
  the four admin-named roles gets the ownership wildcard but **not** the
  permission-check bypass — it still needs `connect.read` granted through
  ordinary `RoleSetHasPermission`, not through `roleSetContainsAdmin`. A
  role literally named `admin` whose actual grants have moved to a
  project-specific scope (no longer global) gets the permission-check
  bypass wherever it's granted, but **not** the ownership wildcard outside
  that scope. This decoupling is deliberate, not a bug — see the two
  paragraphs above.
- **Audit records which gate authorized the read**, as a distinct
  decision reason per branch of the flowchart above: `project_membership`,
  `global_scope`, or `delegation` (exact string tokens are an
  implementation detail, not a design axis — see "Out of scope" and (H)).
  A read authorized via the *permission-check* bypass (step 1/2 above)
  does not by itself change which ownership reason gets recorded — the
  reason names the gate that resolved ownership, not whether `connect.read`
  itself was held directly or cleared via the permission bypass.
- **The retained `{0,0}` scope entry is now load-bearing for ownership
  resolution.** A future refactor that "cleans up" the raw scope list back
  down to `ProjectID != 0` — exactly what the prior draft of this ADR
  itself did, and what would look like harmless dead-code trimming to
  someone unfamiliar with this design — would silently and completely
  remove every global-scoped caller's Connect reach, with no error, only a
  support ticket weeks later. **The implementation phase must add a named
  invariant test asserting the `{0,0}` entry survives the
  scope-derivation-to-ownership-comparison path uncut.** The exact test
  name is an implementation detail, but it must state the invariant in its
  own name — e.g. `TestConnectOwnership_ZeroScopeEntryMustSurvive` — so a
  future removal fails with a message pointing at this ADR's design, not a
  silently-discovered production authorization regression.
- **A read denied by ownership (with no matching `ConnectRefGrant`
  delegation) returns the exact same shape as an unknown connector**
  (`ErrConnectUnknownConnector` — `502`/HTTP, `codes.FailedPrecondition`/
  gRPC, same message text) — a deliberate choice, not an oversight.
  `ListConnectors` already omits a connector the caller cannot reach from
  discovery (E); returning a distinguishable "exists, but you can't read
  it" response on the single-connector read path would let a caller probe
  for a connector's existence by trying names one at a time, defeating that
  omission. **This costs operator debuggability**: a caller who genuinely
  mistyped a connector name and a caller who is correctly denied ownership
  see an identical error, so a legitimate misconfiguration (a typo in
  `connector:`) cannot be distinguished from a correct denial by the
  response alone. The audit event (branch 3) is the intended remedy for
  this: the three-way decision reason (`project_membership` /
  `global_scope` / `delegation`) never populated on a genuine denial is
  visible to whoever can read the audit trail (an operator debugging their
  own misconfiguration, or a security reviewer), even though it is
  invisible to the caller who received the response.

### F. `ConnectRefGrant` (ADR-045) retained unchanged as the cross-project delegation path

Same `(role, connector, ref_prefix)` shape, same glob/prefix matching
(`refMatches`), same expiry handling, same audit events, same bare-string
`Connector` reference — no schema or behavior change to `ConnectRefGrant`
itself. Its role narrows from "the only control beyond the coarse global
permission" to "the explicit, per-role, audited mechanism for one project
to borrow another project's (or a platform-scoped) connector" — the job it
already had, now with ownership handling the case it was never actually
designed to cover.

### G. Reserve `environment:` in config now; enforcement is a follow-up ADR

A `project`-scoped connector config entry may optionally carry an
`environment:` key. **It is accepted and stored, but not enforced by this
ADR** — every environment within the owning project is currently treated
identically for authorization purposes regardless of whether
`environment:` is set. This is declared explicitly (not silently ignored)
so:

- the config key exists and is stable once an operator starts using it,
  avoiding a second config-schema change when enforcement ships;
- enforcement semantics (does a caller need project-level *and*
  environment-level membership? does an unset `environment:` mean "all
  environments" the same way (E)'s project check works today?) are a real
  design question deserving its own ADR, not a rider on this one;
- no deployment can currently rely on `environment:` for actual access
  control — the doc/config comments for this key must say "reserved,
  not yet enforced" plainly, not merely omit mention of enforcement.

### H. Audit surface: switch to `writeAuditEventFull`, populate the connector's owning project, record which gate authorized the read

Every Connect audit event (`connect.secret_read`, success and denial alike)
switches from `writeAuditEvent` to `writeAuditEventFull`, populating the
existing `AuditEvent.ProjectID` column with the connector's **owning**
project (from its config `scope`/`project`) — zero schema change, this
column already exists and is simply unpopulated by Connect today. A
successful read additionally carries a distinct, greppable decision-reason
marker naming which gate in (E)'s order actually resolved ownership:
`project_membership` (caller is a genuine member of the connector's owning
project), `global_scope` (caller's scope set carried the `{0,0}`
global-scope wildcard entry — (E), any role name), or `delegation` (caller
had no ownership claim at all, resolved instead via a matching
`ConnectRefGrant`) — exact
string tokens are an implementation detail, not a design axis. This makes a
cross-project delegation read, and an admin reaching a connector they are
not a genuine member of, both distinguishable from an ordinary same-project
read in an audit review, rather than all three being indistinguishable
successful reads. This mirrors the numeric-at-storage, resolved-at-export-layer
split already established for `impersonated_by`/`acting_as` (numeric FK at
the `AuditEvent` row, resolved to an email string only at the HTTP
export/API layer) — the same convention, not a new one.

### I. ADR-045 is explicitly amended, not silently superseded

`docs/adr-045-connect-per-reference-rbac.md` gains an "Amended by ADR-082"
notice under its `## Status` header, and its Context section's line
"since Connect is a global surface" is revised to reflect that Connect now
has a per-connector ownership boundary — `ConnectRefGrant` itself is
unchanged (F), but the assumption it was reasoned about under is not. This
edit lands in the same change as this ADR's acceptance, not deferred.

## Rejected alternatives

(Carried forward from the prior draft; still rejected under the revised
design, with (D) added.)

- **`ProjectID uint` (nullable) added directly to `ConnectRefGrant`.**
  Conflates ownership (a connector attribute) with delegation (a per-role
  exception). A grant's absence would ambiguously mean "not delegated" or
  "not owned"; "which project owns this connector" would need a full table
  scan instead of one config lookup.
- **Project-scoped `connect.read` permission variant.** Leaves nothing to
  compare a project-scoped permission *against* if the connector itself
  carries no ownership attribute; breaking for every existing global
  `connect.read` holder with no equivalent amortization to (C)'s single
  boot-time gate.
- **Nullable `project`, no `scope` enum.** A missing value must never be a
  legitimate, indistinguishable-from-intentional steady state for a live
  authorization boundary — the same reasoning behind (C)'s hard boot
  failure.
- **Caller-supplied project ID as a request parameter.** Rejected in (D):
  a client-asserted value is a hint an attacker controls, not a boundary
  the server can trust for an authorization decision, when the same
  information is already derivable authoritatively from role-assignment
  storage.
- **A DB table mirroring connector metadata**, decided against explicitly
  in (A) rather than left as an open question — no runtime CRUD exists to
  make the mirror pay for itself yet.
- **Admin bypass short-circuiting the ownership check** (i.e., having
  `roleSetContainsAdmin` skip past (E)'s ownership comparison entirely for
  admin-named roles, the way it already skips the `connect.read`/
  `connect.platform.use` permission checks). Rejected in favor of the
  scope-set-expansion mechanism (E): a control-flow bypass makes the access
  decision invisible at the point where ownership is evaluated — nothing in
  that code path would record *why* access was granted, unlike a wildcard
  entry flowing through the same comparison and the same audit
  decision-reason logic every other caller's read produces. This is the
  Kubernetes `system:masters`-vs-hardcoded-superuser distinction, applied
  here. **Also rejected for a second, independent reason**: `roleSetContainsAdmin`
  itself is name-based (`GetRoleByName` against `adminRoleNames`), and
  copying its shape for ownership would have inherited that fragility —
  the chosen mechanism (E) keys off grant *scope* instead, deliberately
  avoiding it.
- **Keying the ownership wildcard off `adminRoleNames` (role name), the way
  `roleSetContainsAdmin` identifies admin for the permission-check
  bypass.** Considered and rejected on verification (E): `Role` carries no
  structural `IsSystem`/`IsGlobal` marker, only a mutable, merely-unique
  `Name` column — a role renamed away from an admin-named string would
  silently lose the wildcard, and (in principle) a customer role that ends
  up holding one of the four reserved names would silently gain it. The
  scope-based rule adopted instead (E) needs no new predicate and matches
  this codebase's own existing `scopedRoleIDs` union behavior for ordinary
  permission checks.

## Out of scope for this ADR

- Enforcement semantics for `environment:` (G) — its own follow-up ADR.
- The GCP `gcp-secret-manager` connector's own `project_id` field and its
  current boot-warning-only (not enforced) behavior (#431) — a real,
  separate gap at the ambient-cloud-identity layer, unrelated to Keyorix's
  `Project` entity; not fixed by this ADR.
- The exact `connect.platform.use` permission description string and the
  exact delegation-audit decision-reason marker text — implementation
  detail, not a design axis.
- Web UI / CLI surfaces for viewing a connector's `scope`/`project` or the
  boot-time unscoped-connector warning list — follow mechanically from
  (A)-(C) once shipped, not a design question this ADR resolves.
- An operator-facing `ConnectorProjectBinding` management surface (view/
  clear a stale binding after a confirmed intentional project rename — see
  (A.1)). The remediation path today is a direct DB action (remove the
  stale `connector_project_bindings` row, then restart); a proper admin
  surface for this is a real follow-up, not decided or built here.
- Regenerating the gRPC proto is **not needed** — (D) explicitly keeps the
  wire shape unchanged.
- **Splitting "read across all projects" from "administer all projects"
  into separate permissions** (Doppler's distinction between its
  `Access All Projects` and `Admin on All Projects` roles). This ADR grants
  a single, undifferentiated all-projects Connect-ownership reach to any
  global admin-named role (E) — the same roles that already implicitly
  reach every project for ordinary RBAC-gated actions via the existing
  global-role-union behavior in `scopedRoleIDs`/`Authorize`. Whether
  Connect (or RBAC generally) should offer a narrower "can read everything,
  cannot administer" tier is a real, separate design question worth its own
  follow-up ADR; not decided or implemented here.
- **`roleSetContainsAdmin`'s name-based admin identification**
  (`authz.go:346-364`, resolving `adminRoleNames` via `GetRoleByName`
  rather than a structural role property). Verified during this ADR's
  review as a real, pre-existing fragility: a role renamed away from an
  admin-named string silently loses the permission-check bypass, and —
  since `Role.Name` is only unique, not otherwise protected — a customer
  role that ends up holding one of the four reserved names would gain it.
  (E)'s own ownership wildcard deliberately avoids inheriting this shape
  (it keys off grant *scope*, not role *name*), but this ADR does not fix
  `roleSetContainsAdmin` itself; that is a separate, standalone issue
  affecting the ordinary permission-check bypass everywhere (not only
  Connect) and needs its own fix on its own branch.

## Consequences

**New permission, and which existing roles need it.** `connect.platform.use`
is new. Today, both roles that carry `connect.read` in the seeded role
catalog — `admin` and `system_admin` (both built from the same
`adminPermissions` list, `auth_bootstrap.go:89-95`) — must gain
`connect.platform.use` added to that same list, or they lose the ability to
reach `platform`-scoped connectors they could reach unconditionally before
this ADR. (`project_admin` does not carry `connect.read` today and is
unaffected the same way it already couldn't use Connect at all without an
additional grant.) Note for implementation: `admin`/`system_admin` already
bypass ordinary permission checks via `adminRoleNames` (E) — adding
`connect.platform.use` to their explicit list is for audit-visibility and
custom-role-cloning clarity, matching why `connect.read` itself is already
listed there despite the same bypass, not because the bypass wouldn't
otherwise cover it.

On upgrade, an already-provisioned installation does not need a fresh
bootstrap to pick up this change: `ReconcileRBACPermissions`
(`internal/core/rbac_reconcile.go`, ADR-044) runs unconditionally on every
boot (`server/main.go:311`, best-effort, non-fatal on error) and additively
tops up any newly-added canonical permission — including
`connect.platform.use` once it's added to `adminPermissions` — onto
existing `admin`/`system_admin` role rows, without clobbering any other
permission or role state. `bootstrapSystemLocked`'s seeding path, by
contrast, only ever runs on a deployment's very first boot ever
(short-circuited by the `systemInitializedKey` guard in `system_metadata`
on every subsequent boot) — it is `ReconcileRBACPermissions`, not the
bootstrap seeder, that actually carries this permission to already-running
installations.

**Boot-failure upgrade impact, the release it lands in, and the required
CHANGELOG entry.** This is a breaking change to server boot behavior,
targeted at **`v0.92.0`** — the next minor release following this
repository's existing versioning (`v0.91.0` is current at time of writing;
`v0.92.0` is the earliest this could ship in, not a fixed commitment ahead
of implementation). Any existing deployment with `connect.enabled: true`
and one or more configured connectors **will fail to boot** after upgrading
unless every connector gains an explicit `scope`, or the deployment sets
`connect.allow_unscoped: true` as an explicit, intentional stopgap (with the
every-boot `WARN` noise that implies). This requires a **`BREAKING`**-labeled
CHANGELOG entry for that release — the same handling ADR-076 gave its own
default-scope change (that ADR's Consequences section: "Two separate
CHANGELOG entries, not one" — `BREAKING` for the behavior change itself).
The entry must state the required pre-upgrade config change plainly, not
just "review your config" (ADR-076's own precedent for what counts as
adequate here), and must name the exact new keys (`scope`, `project`,
`connect.allow_unscoped`) an operator needs to act on.

**Why config-only was chosen over a DB mirror.** Stated directly in (A):
there is no runtime connector-CRUD capability today, so a DB row would add
migration surface, a second source of truth to keep in sync with the YAML
an operator actually edits, and a join at every authorization check — for
zero capability gained until a genuinely different feature (runtime
connector management via API) exists to justify it. Config-only keeps this
ADR's blast radius to exactly the ownership question it exists to answer.

**Positive.** Closes `connect-findings.json#2` at its actual root — the
connector now carries its own ownership, evaluated before `ConnectRefGrant`
delegation rather than that grant table being asked to answer a question
it was never designed to hold. `ConnectRefGrant`/ADR-045 keeps its existing
shape and tests untouched. The audit surface (H) is directly usable for
NIS2/DORA least-privilege evidence. The boot-time-fail-loud gate (C) means
a future config mistake (a new connector added without `scope`) is caught
at the next restart, not silently left unscoped indefinitely the way the
GCP `project_id` gap has been.

**Negative.** `admin`/`system_admin`'s seeded permission list changes (new
`connect.platform.use`, see above). **Any role granted at the global scope
and holding `connect.read` — not only `admin`/`system_admin`, and not
contingent on role name — now reaches every `scope: project` connector's
ownership, per (E)'s deliberate scope-based rule.** In the seeded role
catalog this only affects `admin`/`system_admin` today (the only roles
carrying `connect.read`), but an operator who creates a custom role, grants
it `connect.read`, and assigns it at the global scope gets the same reach —
a real, intentional consequence of (E)'s rule, not an edge case to guard
against; an operator who wants a `connect.read` holder *without*
all-projects reach must assign that role at a project scope, not the
global one. `ListConnectors` behavior changes for any caller whose
`connect.read` is held at a project scope (not global) and who is not a
member of every project with a connector — a caller who previously saw
every connector name now sees only the ones they can reach (project
membership or delegation), which could surprise an integration that
enumerates connectors expecting the full list. This does not affect
global-scoped `connect.read` holders (in practice, `admin`/`system_admin`
today), who retain full visibility under (E) — no behavior change for them
relative to today. (The boot-time upgrade-action requirement is already its
own Consequences entry above and isn't repeated here.)

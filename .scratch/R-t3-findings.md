# Adversarial review — machine-identity role grant/revoke path (t3)

Target: `changeMachineRole` (server/http/handlers/machine_identities.go), and
`AssignMachineRole` / `RemoveMachineRole` + the scope/authority checks under them
in internal/core.

## Scope-of-grant claim: verified, NOT a defect

The `GrantMachineRole` doc (machine_identities.go:485–486) claims "The role is
granted at the project scope." I attempted to disprove this (a request scope
field being ignored, or a narrow grant taking effect broadly). It holds:

- The grant request body (changeMachineRole, lines 513–521) carries ONLY
  `role_id`. There is no environment / scope field in the body, so there is no
  request-supplied scope being silently dropped or over-applied.
- The handler builds `scope := core.Scope{ProjectID: uint(projectID)}`
  (machine_identities.go:531), i.e. `EnvironmentID == 0` — project-wide, exactly
  as documented.
- The storage interface `AssignMachineRole(ctx, machineID, roleID, scope)`
  (internal/core/storage/interface.go:583) is the only machine-role grant path;
  machine roles are only ever project-scoped in this codebase (no
  environment-dimension machine grant exists anywhere). So nothing is lost by the
  handler not threading an EnvironmentID.
- The route gate `RequireScopedPermission(permRolesAssign, projectScope)` with
  `projectScope = ScopeFromProjectParam("id")` (router.go:455, 582–583) resolves
  the SAME `{id}` path param to the SAME `Scope{ProjectID}`, and
  `AssignMachineRole`'s ceiling check (`requireGranterHoldsRolePermissions`) is
  called with that same scope. Gate scope, ceiling scope, and persisted scope are
  identical — no scope-confusion gap.

`machineInProject` (machine_token.go:52–58) additionally pins the target machine
to `scope.ProjectID`, and the global-scope (ProjectID 0) case is structurally
unreachable for a real machine (every machine has a nonzero ProjectID; see
machine_global_scope_invariant_test.go). No cross-project or scope-broadening
grant is reachable here.

Classification: EXPECTED-DIFFERENCE / no finding on the scope axis.

## Self-machine-granter path: verified sound

When a directly-authenticated machine actor calls the grant route, the handler
tags ctx with `WithSelfMachineGranter(actor.PrincipalID())` and passes
`actorIsMachine=true` (machine_identities.go:534–541). The ceiling check then
resolves the granting MACHINE's own permissions via
`AuthorizePrincipal(ActorTypeMachine, selfMachineID, …)`
(authz.go:1039–1049), requiring it to hold `roles.assign` AND every permission
the target role bundles, at that project scope. An untagged machine ctx
(e.g. a would-be relay) fails closed (checkGranterHoldsPermission's
`actorIsMachine` default branch returns `false, nil`). The actor's principal ID
is used for the self tag, the URL `{machineId}` is the target — no actor/target
confusion. This matches the CLAUDE.md "ceiling must derive from the ACTOR, not
only the target" rule. No escalation found.

## Finding 1 — RemoveMachineRole runs no authority ceiling / SoD check

- Classification: HARDENING (benign by analysis)
- File:line: internal/core/machine_token.go:462–472
- Claim examined: by symmetry with `AssignMachineRole` one might expect a ceiling
  check on removal too; there is none (only `machineInProject`, then
  `storage.RemoveMachineRole`, then audit).
- Why it is not a vulnerability: removing a role strictly REDUCES the target's
  privileges, so it is not a self-escalation vector for the actor; the route is
  gated by `roles.assign` at the project (router.go:583). There is no
  "remove to escalate" here (no SoD obligation is enforced by a role's PRESENCE
  that removal would unlock). Noted only because the asymmetry is worth a one-line
  doc comment so a future reviewer does not mistake the missing check for an
  oversight.
- Confidence: HIGH (that it is benign).

## Finding 2 — Machine granter not recorded in the audit UserID column

- Classification: DEFECT (audit attribution), LOW severity
- File:line: internal/core/machine_token.go:456 → machine_identities.go:354–358
  → audit.go:274–294
- Observation: for a machine-credential granter, `actor.UserID == 0`
  (machine tokens carry UserID 0), so `logMachineEvent` writes `UserID = &0`.
  `writeAuditEventDiff` stamps `ActorType` from ctx (correctly "machine") but does
  NOT consume the `WithMachineActor` tag to record WHICH machine identity granted
  the role. So the audit row for `machine_identity.role_granted` shows actor
  type = machine but actor id = 0 — the specific granting machine is not in a
  queryable column.
- Trigger: a machine identity holding `roles.assign` + the role's bundled perms
  POSTs `/api/v1/projects/{id}/machine-identities/{machineId}/roles`; the grant
  succeeds and is audited with no identifiable granting principal.
- Reachability: live. Route `POST /projects/{id}/machine-identities/{machineId}/roles`
  (router.go:582) → `GrantMachineRole` → `changeMachineRole(grant=true)` →
  `AssignMachineRole` → `logMachineEvent`. A machine token authenticates and
  reaches this via the self-granter branch.
- Caveat: this is a pre-existing, path-wide treatment of machine actors in audit
  (not specific to this grant), and it is an attribution gap, not an authz gap —
  the grant itself is correctly authorized against the machine's real permissions.
- Confidence: MED (that the attribution is incomplete); not a privilege defect.

## Overall

No VULNERABILITY or SECURITY-DEFECT found on this path. The scope-of-grant
behaviour the doc claims is accurate and consistently enforced across the route
gate, the core ceiling check, and the storage write; the machine self-granter
ceiling is correctly derived from the acting principal and fails closed when
untagged. The two items above are a benign asymmetry and a low-severity audit
attribution gap.

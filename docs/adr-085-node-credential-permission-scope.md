# ADR-085: Node credentials should carry their own narrow permission set, not an OR-bypass of the permission system

## Status

**Proposed.** This ADR answers a design question raised by the G80 CI-baseline
campaign's `actorID(r)` sweep (#1524, #1529, #1530, #1531). It makes **no
code changes** — the two findings below are filed and, per explicit
instruction, not patched here. Implementation, if this ADR is accepted, is
its own follow-up work with its own review.

**Update (2026-08-23) — central recommendation is blocked, and no longer
launch-blocking:**

- **Blocked.** The route classification done for #1532 (comment on that
  issue) confirms this ADR's recommended fix — give `MachineTypeNode` its own
  scoped permission set via ADR-030's `machine_identity_roles`/
  `AuthorizePrincipal` mechanism — cannot close findings (b) `AddGroupMemberProxy`
  or (c) `ApproveRiskExceptionProxy` as proposed. Both are **per-actor
  ceilings**: they need to know *which specific human* is acting (is this
  human already an admin-conferring-group member who can add another; is
  this human someone other than the exception's creator). A node identity,
  scoped or not, is not and cannot become a specific human — `AuthorizePrincipal`
  answers "is this principal allowed," never "which human does this
  principal act on behalf of," and `core.CreateMachineIdentity` (`internal/core/machine_identities.go:75`)
  independently rejects `projectID == 0`, so a node identity can never hold a
  *global-scope* role even if this ADR's mechanism were built — and both
  ceilings are checked at global/admin scope. Scoping the node's permission
  set narrower does not change that a node has no per-actor identity to
  check against. See "The two ceiling types" below — this is a structural
  property of the ceiling, not a gap this ADR's proposed mechanism happens
  to leave open.
- **No longer launch-blocking.** Findings (b) and (c) are fixed independently
  of this ADR's decision, by a narrower rule that needs no new mechanism: a
  machine actor may not perform an operation whose safety depends on knowing
  which human is acting — deny, fail closed (matching the precedent already
  set by `CreateUserWithRoleGrantsProxy`). That fix is implemented, tested,
  and adversarially verified (branch `fix-1524-machine-actor-fail-closed`).
  This ADR's open question — whether `MachineTypeNode` should carry its own
  scoped permission set at all — remains real and worth deciding, but nothing
  here still blocks shipping.
- **Decision needed by 2026-09-15.** No code depends on this ADR being
  accepted or rejected; it will not force a build failure if left open. It is
  tracked here, not enforced, so it needs an explicit owner and date or it
  will age quietly — see `docs/adr-085-node-credential-permission-scope.md`
  itself as the tracking artifact until a decision lands.

## Context

### The current gate, and why it exists

`server/http/router.go:1088-1089` gates the entire `/system` route group —
every `RemoteStorage`-sync proxy handler in `server/http/handlers/*_proxy.go`
— with `RequireNodeCredentialOrPermission(permSystemWrite)`
(`server/middleware/node_credential.go`): a node-type machine credential
(`core.MachineTypeNode`) **or** the `system.write` RBAC permission.

This is itself the fix for an earlier problem (#G79, router.go:1061-1084):
the group used to be gated by plain `RequirePermission(system.write)`, a
normal RBAC permission string. `system.write` is intentionally grantable to a
narrow, documented custom role (audit checkpoints, legal holds, risk
exceptions, SoD policies, admin job triggers). Granting that role for its
documented human-facing purpose *also* silently handed the grantee the
ability to act as a trusted downstream node — an unrelated capability
riding along on an unrelated grant. G79 split that into two explicit arms.

A pure node-credential-only gate was tried and reverted (router.go:1072-1078,
"a pure node-credential-only gate was tried and reverted"): several routes
nested in this same group — legal-hold, risk-exceptions, SoD policies — are
also `system.write`'s own legitimate, documented human-facing footprint, and
their `internal/core` functions already self-check for admin-tier RBAC
authority. A node credential deliberately carries zero RBAC permissions
(`core.MachineTypeNode`'s own doc comment, `machine_identities.go:34-39`:
*"it carries no implicit RBAC permission of its own and must never be
included in any role's default/admin permission bundle"*), so a node-only
gate would have made those legitimate admin features **unreachable** via
`storage.type: remote` — a real regression, not a hypothetical one.

So the OR-gate is not an oversight. It is the considered resolution of a
genuine conflict between two populations of routes sharing one URL prefix:
routes whose only legitimate caller is a relaying node, and routes whose
legitimate callers are real RBAC-authorized humans **and** relaying nodes
(the whole premise of ADR-049's remote-storage relay: a downstream server's
already-authorized human action gets replayed against the upstream's real
storage). The router.go comment already flags that this doesn't fully close
the concern: *"adminRoleNames unconditionally bypass every permission check,
so any admin-tier role holder still reaches this whole surface via the
permission arm regardless of what's explicitly bundled into their role."*

### What the OR-gate actually costs: two confirmed findings

The `actorID(r)` sweep (#1524) found that `actorID(r)`
(`server/http/handlers/catalog.go:19`) collapses two genuinely different
callers onto the same value: a real user session with `UserID` present, and
*anything else* — including a legitimately-authenticated node credential —
returns `0`. Downstream code has no way to distinguish "no session, and this
is fine" from "no session, and this is actually a relay with no per-action
authority attached." Two confirmed, live consequences:

1. **`AddGroupMemberProxy` → `AddUserToGroup`** (`groups.go:240`):
   `if actorID != 0 { validateGroupJoinRoles(...) }` — the escalation-by-proxy
   ceiling and SoD check on joining an admin-conferring group is written as
   an explicit exemption for a "trusted local CLI" (`actorID == 0`). A node
   credential produces the identical zero. **A node credential can add a
   user to an admin-conferring group with the ceiling check never
   evaluated at all — the user is now a global admin.** Confirmed reachable:
   `AddGroupMemberProxy` sits in the same node-credential-gated block as
   every other group route.

2. **`ApproveRiskExceptionProxy` → `ApproveRiskException`**
   (`risk_exceptions.go:234`): the dual-control self-approval guard is
   `actorID == e.CreatedBy`. A risk exception created by a real human
   (`CreatedBy=5`) and approved by a node credential (`actorID=0`) does not
   collide — the guard passes, and the approval proceeds with **no authority
   check of any kind**. Dual control's entire purpose (a creator cannot
   unilaterally suppress a violation of their own) is bypassable by any node
   credential in exactly the case that matters: a human proposes, a machine
   "approves."

A third, related-but-distinct class (#1529): several sites in the same
route group (`DeleteSoDPolicy` most concerning) have **no** actor-authority
check to bypass in the first place — `system.write` alone, human or node,
is treated as sufficient. And a fourth (#1530): even a fully legitimate
relay call ends up persisting `CreatedBy=0`/`RevokedBy=0` on governance
records, because the wire protocol carries no acting-user identity across
the hop at all.

### The two ceiling types — why this isn't a binary "close the gate or don't"

The route classification for #1532 sorted every `RequireNodeCredentialOrPermission`
route by what kind of check its `internal/core` function needs, and found the
gap is not uniform across the group — it splits cleanly into two kinds:

- **Target-state-invariant checks** — the check depends only on the state
  being mutated, never on who's asking. `RemoveGlobalAdminRoleGuardedProxy`'s
  "would this strand the last admin" check, or `RemoveGroupMemberProxy`'s
  equivalent, are safe for *any* caller including a bare node credential, by
  construction: the question "does zero admins remain" has the same answer
  regardless of who's asking it. These routes were never actually exposed by
  the OR-gate in the way this ADR originally assumed — they self-protect
  regardless of which arm of the gate let the caller in.
- **Per-actor ceiling checks** — the check is defined in terms of *which*
  human is asking: is this human already a member with standing to add
  another (`AddGroupMemberProxy`), is this human someone other than the
  exception's own creator (`ApproveRiskExceptionProxy`). These cannot be
  satisfied by a node credential, scoped or not, because a node is not a
  human and carries no "which human" to check — narrowing what a node is
  *allowed to attempt* doesn't give it an identity to check *against*.

This ADR's original framing treated "should a node bypass the permission
arm" as one binary question with one mechanism (a scoped permission set) as
its answer. It isn't. Target-state-invariant routes need no fix at all — the
OR-gate never put them at risk. Per-actor-ceiling routes need a fail-closed
rule that has nothing to do with what permissions a node carries — see
"Update" above. A scoped permission set is orthogonal to both: it would
narrow a node-legitimate route's blast radius (a real, separate benefit) but
does not and cannot touch a per-actor ceiling either way.

### Prior art already in this codebase

ADR-030 (machine-token authentication) already built the mechanism this ADR
is asking whether `MachineTypeNode` should also use: `machine_identity_roles`
+ `AuthorizePrincipal(ctx, actorType, principalID, permission, scope)` —
scoped, least-privilege, auditable roles for non-human principals, with
admin-role bypass **deliberately excluded** for machines ("a machine is
never a global admin," ADR-030 Decision → Authorization). General machine
identities (CI, k8s, automation, service, other) already go through this.
`MachineTypeNode` is carved out from it by its own doc comment, specifically
so it stays a bare, permission-free relay identity — that carve-out is the
thing this ADR asks whether to keep.

## The design question (re-scoped)

Originally framed as: should `RequireNodeCredentialOrPermission` continue to
let a node credential bypass the permission arm entirely, or should node
credentials carry their own narrow, scoped permission set via ADR-030's
`machine_identity_roles`/`AuthorizePrincipal` mechanism? The "Update" above
and "The two ceiling types" section explain why that framing doesn't hold up
as a single binary — the per-actor-ceiling routes this ADR was originally
motivated by are fixed by a fail-closed rule that has nothing to do with
what a node is scoped to do, and the target-state-invariant routes were
never actually at risk from the OR-gate.

What's left, and still genuinely open, is narrower: **should machine
identities — starting with, but not limited to, `MachineTypeNode` — be able
to hold global-scope roles at all?** Today `core.CreateMachineIdentity`
(`internal/core/machine_identities.go:75`) rejects `projectID == 0`
unconditionally; every machine identity is project-scoped by construction.
That constraint is *why* the scoped-permission-set idea in this ADR's
original decision can't reach any of the node-legitimate routes classified
as global-scope for #1542 (`AssignRoleWithExpiryProxy`,
`AssignRoleToGroupWithExpiryProxy`, `AssignMachineRoleProxy` chief among
them) — a node's own permission set, however narrowly scoped, is inert at
global scope if the node can never hold a global-scope grant in the first
place. Answering this question decides whether a scoped-permission-set
mechanism for nodes is even buildable as originally envisioned, or whether
the project-scope constraint needs to be revisited first (its own separate
decision, with its own blast-radius analysis — a global-scope machine role
is a materially different risk than a project-scoped one).

A node credential is the single most widely distributed credential class in
a Keyorix deployment — every downstream node running `storage.type: remote`
holds one. "Or it's a node" as an authorization arm makes that credential
class a second, effectively unscoped admin path; the #1532 classification
enumerates **13** `RequireNodeCredentialOrPermission` routes in the RBAC/
governance-mutation scope this ADR is about, correcting the 10 originally
counted here (of 194 total `/system` routes, most unrelated to RBAC/
governance and out of this ADR's scope entirely). The classification also
surfaced routes this ADR's original count missed outright — including
`CreateMembershipProxy`/`UpdateMembershipProxy`, separately flagged in that
table as matching the same raw-storage-bypass shape as #1542 and not yet
checked for reach, an open follow-up and not part of this ADR. See the full
table on #1532 for the per-route breakdown and classification. Route-fourteen
drift is now caught structurally: `server/http/node_credential_route_classification_test.go`
fails CI if a route is added to this gate without being classified, closing
the "next handler inherits the gap silently" problem this ADR originally
raised as unaddressed.

### A second, harder question this ADR does not resolve

Giving node credentials their own scoped permission set closes the crude
binary bypass (a node can currently do *everything* `system.write` can, not
some narrower relay-appropriate subset). It does **not**, by itself, solve
attribution or per-action ceiling checks for a *legitimate* relay: the
problem in finding 2 above is not "should this node be allowed to call
approve at all" (yes — that is the entire point of ADR-049's relay) but
"whose authority is this approval actually exercised under" — the real
answer lives on the *downstream* server, with the human who clicked
approve, and today's wire protocol has no field carrying that identity
across the hop at all (this is #1530's unattributed-audit-rows finding,
restated as a design gap rather than a persistence gap). A node-scoped
permission set answers "is this node allowed to relay approvals," not "is
the person this approval is attributed to allowed to approve this specific
one" — those are different questions, and only the first is what this ADR
proposes deciding now.

## Decision (proposed)

**Recommend: give node credentials their own narrow, scoped permission set**
via ADR-030's existing `machine_identity_roles`/`AuthorizePrincipal`
mechanism — e.g. a dedicated capability (not `system.write` itself, to avoid
recreating G79's original conflation) scoped to exactly the relay operations
a node legitimately needs — **and split this route group's two populations**
so that routes with a genuine per-actor ceiling or dual-control check
(admin-role reinstatement, group-membership escalation ceiling, risk-exception
approval) either:

- deny a node-credential caller outright when the underlying `internal/core`
  function has no legitimate node-caller answer for that specific ceiling
  (matching what several sites — `PlaceLegalHold`, `LiftLegalHold`,
  `RestoreProject`/`RestoreEnvironment`/`RestoreGroup`'s admin-tier branch —
  already do correctly today, by accident of how `IsGlobalAdmin(ctx, 0)`
  resolves), or
- require a separate, explicit mechanism for carrying the downstream
  server's asserted acting-user identity across the wire, with its own trust
  model for whether the upstream should believe that assertion — this is the
  "harder question" above, and is its **own** follow-up decision, not
  bundled into this one.

This directly reduces to reusing infrastructure ADR-030 already built and
already runs in production for every other machine-identity type; the
proposal is to stop excluding `MachineTypeNode` from it, not to invent a new
mechanism.

### Why not leave the OR-gate as-is and patch call sites individually

This is the status quo, and it is what #1524/#1529's two confirmed findings
already got (fixture quarantines + issues, not silent fixes). It is a
reasonable *stopgap* for the two confirmed cases — narrowing
`actorID != 0` at `groups.go:240` and adding a real ceiling check to
`ApproveRiskException` for a node-relay caller specifically — but does not
change that the *pattern* (node-ness alone satisfies a permission gate whose
routes assume a scoped, checked caller) stays in place for every future
route added to this group. Given a node credential's blast radius (every
deployed spoke), the recommendation is to close the pattern, not just its
two current instances.

### Why not remove the OR-gate and require every node to hold `system.write` via a real role grant

Considered and rejected: this reintroduces exactly the G79 problem the
current gate exists to avoid — `system.write` is a real RBAC permission
grantable to humans for its own documented, unrelated purpose (audit
checkpoints, legal holds, admin job triggers), and a human holding it for
that reason would once again incidentally gain full node-relay capability.
The two capabilities (human system-administration actions, node-relay
actions) need to stay on separate permission surfaces, which is exactly what
a dedicated node-scoped capability (this ADR's recommendation) gives without
recreating the conflation.

## Evidence

- #1524 — original node-credential/RBAC-mutation reachability sweep (9
  routes), extended with the `AddGroupMemberProxy` ceiling-bypass finding and
  the `ApproveRiskException` dual-control-bypass finding (10 routes total at
  the time). #1532's full classification corrected this to 13 routes — see
  "The design question (re-scoped)" above.
- #1532 — the route classification comment: full table of all 13 routes with
  file:line, per-actor-ceiling vs target-state-invariant vs node-legitimate
  classification, and the completeness-guard test that keeps it from going
  stale.
- #1542 — human-reachable global-admin escalation via 4 raw-storage-bypass
  proxy routes (`AssignRoleWithExpiryProxy`, `AssignRoleToGroupWithExpiryProxy`,
  `AssignMachineRoleProxy`, `RemoveAllProjectRoleGrantsProxy`), found while
  verifying #1532's classification. Independent of node-credential status —
  affects any `system.write` holder — and launch-blocking in its own right,
  not part of this ADR's decision.
- #1529 — sites with no actor-authority check at all (a distinct but
  related gap; `DeleteSoDPolicy` flagged most concerning).
- #1530 — unattributed audit rows for legitimate relay calls (the
  "harder question" above, restated as a persistence-layer symptom).
- #1531 — unrelated wire-contract bug found while correcting a
  misdiagnosed quarantine reason; not evidence for this ADR, noted only so
  it isn't conflated with the findings above (it produces a loud error, not
  a silent bypass).
- ADR-030 — the `machine_identity_roles`/`AuthorizePrincipal` mechanism this
  ADR proposes extending to `MachineTypeNode`.
- `core.MachineTypeNode`'s doc comment (`machine_identities.go:34-39`) — the
  current invariant this ADR proposes revisiting.
- router.go:1052-1089 — G79's own reasoning for the current OR-gate,
  including its self-flagged admin-role-bypass caveat.

## Out of scope

- Implementing the node-scoped permission set or the route-group split, if
  this ADR is accepted — its own follow-up work with its own review.
- The two confirmed findings (#1524's `AddGroupMemberProxy`/
  `ApproveRiskException` items) are **no longer** gated on this ADR — see
  "Update" above. They're fixed independently by a fail-closed rule for
  machine actors on per-actor-ceiling operations, not by anything this ADR
  decides.
- Designing the downstream-actor-identity wire mechanism (the "harder
  question"). Flagged as a second, later ADR if the team wants to pursue it;
  not decided here.
- #1529 (no-check sites) and #1530 (unattributed audit) beyond citing them
  as evidence — both are already filed as their own issues with their own
  per-site recommendations.
- #1531 (wire-contract mismatch) — unrelated bug, not part of this design
  question.

## Consequences (if accepted)

- Node credentials stop being an unscoped bypass of the **node-legitimate**
  routes in this group and become a bounded principal type like every other
  machine identity — narrowing blast radius on routes like
  `AssignRoleWithExpiryProxy`/`AssignMachineRoleProxy` (also implicated in
  #1542, independent of this ADR). This does **not** close the per-actor-
  ceiling routes (`AddGroupMemberProxy`/`ApproveRiskExceptionProxy`) — those
  are already fixed, independently, by the fail-closed rule described in
  "Update" above, and stay fixed regardless of this ADR's outcome.
- The per-route classification this consequence used to require as new work
  already exists and is enforced: #1532's table sorts all 13 in-scope routes
  into node-legitimate / target-state-invariant / per-actor-ceiling, with
  `server/http/node_credential_route_classification_test.go` failing CI if a
  new route joins the gate unclassified. Accepting this ADR would add a
  fourth per-route decision on top of that table (does this node-legitimate
  route get a scoped permission, and which one) rather than starting the
  classification from scratch.
- `MachineTypeNode`'s current "carries no implicit RBAC permission" invariant
  is retired in favor of "carries a narrow, explicitly-granted permission
  set" for node-legitimate routes — a real behavior change for every node
  credential in every existing deployment, requiring a migration/rollout
  story (out of scope here, part of implementation) — and only matters once
  the re-scoped open question ("should machine identities hold global-scope
  roles?") is answered, since several node-legitimate routes classified for
  #1532 are global-scope operations a project-scoped machine identity cannot
  reach today regardless of what permission set it's given.

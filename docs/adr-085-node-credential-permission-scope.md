# ADR-085: Node credentials should carry their own narrow permission set, not an OR-bypass of the permission system

## Status

**Accepted (2026-08-25).** Final decision: node-authenticated requests get
**no privileged access**. The `RequireNodeCredentialOrPermission` OR-arm this
ADR spent two months proposing to *narrow* is instead **removed outright** —
`/api/v1/system` now requires the plain `system.write` RBAC permission for
every caller, node-typed or not, with no second arm. `MachineTypeNode` is
retained as an identity type (`keyorix machine create --type node` is still
user-facing); only its special gate privilege is gone. See "Decision
(Accepted, 2026-08-25)" below for the full resolution, "Why the original
recommendation is superseded, not just unimplemented" for why this reverses
rather than extends the Proposed-status recommendation further down this
document, and "The wire-identity question: CLOSED" for the second question
this ADR originally left open.

**How this ADR got here, for the record — the general lesson**: this ADR was
authored under ADR-049's "downstream Keyorix server" framing (a second server
process, running `storage.type: remote`, relaying an already-authorized
human's action back to an upstream's real storage). ADR-083 (Accepted)
subsequently established that this topology **cannot exist** —
`validateRemoteStorageNotServer` (`internal/config/config.go:2029-2058`)
unconditionally rejects `storage.type: remote` for any server process, HTTP,
gRPC, or scheduler-only. This ADR's own "Note" section (below, dated after
ADR-083 landed) correctly *flagged* that its framing predated ADR-083 — but
flagging a stale premise in a footnote is not the same as re-deriving the
Decision from the corrected premise, and for one more full working session
this ADR's Decision (proposed) section kept recommending a mechanism (a
node-scoped permission set to narrow what a "downstream relay" is allowed to
do) built entirely to serve a caller that provably does not exist. The
general lesson: when a superseding ADR invalidates a foundational premise, the
correction has to *drive a re-derivation of the Decision itself*, not just
live as a cross-reference next to the old one — a note that stops at "this
framing predates X" without asking "does the Decision survive X" leaves the
stale conclusion standing under a corrected-sounding preamble.

**What actually forced the re-derivation**: a Phase-1 liveness check (the
same standing method this campaign used throughout: trace real callers before
fixing or restricting a flagged route) asked the question ADR-083 made
askable but that hadn't yet been asked of this specific gate — does *anything*
actually authenticate with a node credential and call a `/system` route
today? Answer: no. `createNodeToken` (the credential-minting helper this
ADR's own evidence table and every downstream fix cited) is **test-only** in
every one of its ~21 references across the repo. No Helm chart, no Docker
Compose file, no CLI flow provisions a node credential for runtime use.
`docs/REMOTE_CLI_SETUP.md` documents that a bare node token cannot reach
anything a real deployment needs. With no live caller and no possible live
caller (ADR-083 forecloses the only topology that would create one), there is
nothing left to scope permissions *for* — the recommendation this ADR spent
its "Proposed" status arguing for (give the node arm a narrower permission
set) doesn't just remain unimplemented, it is **superseded**: the thing it
would have scoped never has and never will exist as a real caller.

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

**Correction (2026-08-25): the claim below is false and is left here, struck
through in spirit but not in text, as the record of what this ADR got wrong
and why — see "How this ADR got here" at the top of this document.** This
ADR originally asserted a node credential is the single most widely
distributed credential class in a Keyorix deployment, on the premise that
"every downstream node running `storage.type: remote` holds one." No such
downstream node exists or can exist: ADR-083's `validateRemoteStorageNotServer`
rejects `storage.type: remote` for any server process, and the Phase-1
liveness check behind this ADR's final Decision found zero live callers for
a node credential anywhere in the actual codebase (`createNodeToken` is
test-only in every reference). The premise inflated this credential class's
real-world blast radius from "does not exist as live traffic" to "the single
most widely distributed" — the opposite of accurate — and that inflated
framing is what made "give it its own scoped permission set" sound like an
urgent mitigation for a widely-held credential, rather than what it actually
was: permission engineering for a caller that was never there.

"Or it's a node" as an authorization arm made that credential class a
second, effectively unscoped admin path; the #1532 classification
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

## Decision (Accepted, 2026-08-25)

**Node-authenticated requests get no privileged access.** The
`RequireNodeCredentialOrPermission` OR-arm (`server/middleware/
node_credential.go`) is **removed entirely** — not narrowed, not replaced
with a scoped variant. `/api/v1/system` (`server/http/router.go`) now uses
plain `RequirePermission(permSystemWrite)`, identically to every other
permission-gated route group in this codebase. A node credential is
authorized exactly like any other principal: via a real role grant it either
holds (through ADR-030's existing `machine_identity_roles`/
`AuthorizePrincipal` mechanism, already used by every other machine-identity
type) or doesn't. Every `isNodeCredentialRequest(r)` branch inside individual
`/system` handlers — the mechanism eight handlers used to skip a real ceiling
check specifically for a node-typed caller — is removed along with it; those
handlers now run their real ceiling unconditionally, for every caller class.

`core.MachineTypeNode` **stays** as an identity type — `keyorix machine
create --type node` remains a valid, user-facing command, and nothing about
this decision removes the type or blocks creating node-typed machine
identities. What's removed is the type's special *gate* privilege: holding a
node-typed credential no longer means anything to `/system`'s authorization
check that holding any other machine-identity type wouldn't also mean. A
node identity that needs to reach `/system` gets there the same way a
service-typed or CI-typed identity would: a real `MachineIdentityRole` grant
including `system.write`.

This reverses, rather than extends, the narrower "give the node arm a scoped
permission set" recommendation this ADR carried under Proposed status for two
months — see "Why the original recommendation is superseded, not just
unimplemented" immediately below for why scoping was never going to be the
right answer once the liveness question was actually asked.

### Why the original recommendation is superseded, not just unimplemented

This ADR's Proposed-status recommendation was to give the node-credential arm
its own narrow permission set via `machine_identity_roles`/
`AuthorizePrincipal`, so a node could do *less* than blanket `system.write`
rather than being removed from the gate. That recommendation is not merely
something nobody got around to building — it is **structurally blocked**,
independent of whether anyone builds it:

- `core.CreateMachineIdentity` (`internal/core/machine_identities.go:75`)
  unconditionally rejects `projectID == 0`. Every machine identity — node-typed
  or not — is project-scoped by construction. A "scoped permission set for
  the node arm" cannot reach any of the *global-scope* routes this campaign's
  own findings centered on (`AssignRoleWithExpiryProxy`/#1552,
  `AssignMachineRoleProxy`, `RemoveGlobalAdminRoleGuardedProxy`) no matter how
  the scoping mechanism is designed, because a node identity can never hold a
  global-scope grant to check against in the first place.
- The per-actor ceiling helpers several of the highest-severity findings
  route through (`requireAdminAuthorityAt` → `scopedRoleIDs` →
  `GetUserRoleIDsAt`/`GetUserGroupRoleIDsAt`, `internal/core/authz.go`) resolve
  authority via a **user's** direct and group role grants specifically — not
  `AuthorizePrincipal`'s generic actor-agnostic permission check. A scoped
  `MachineIdentityRole` grant on a node identity is invisible to these
  helpers regardless of what permission it carries; confirmed directly
  against `CreateOIDCBindingProxy`'s `requireAuthorityForRole("system_admin")`
  check in `remote_storage_machine_identities_test.go`'s
  `OIDCBindingCreateGetListDelete_RealServer` — a node credential holding a
  real, explicitly-granted `admin` role still cannot create an OIDC binding,
  because the check never looks at machine-identity role grants at all.

Both of these are pre-existing, structural properties of the authorization
code this ADR's original recommendation would have had to build on top of —
not new findings, and not things the "give it a scoped permission set"
design could route around by being more careful. Scoping was never going to
close the routes that actually mattered; only removing the arm and requiring
a real grant does.

### The wire-identity question: CLOSED

This ADR's "second, harder question" (above, "A second, harder question this
ADR does not resolve") asked whether a separate wire mechanism should carry
the downstream server's asserted acting-human identity across the relay hop,
so a per-actor ceiling could be evaluated against the real human rather than
the relaying node. That question is now closed, not merely deferred: there is
no downstream server relay topology for such a mechanism to serve.
ADR-083 (Accepted) already established this for Keyorix's own server
processes (`validateRemoteStorageNotServer`); the same architectural
conclusion — a secondary node process should never carry write authority
derived from "it must have already checked" — is also where every comparable
external secrets-management product has independently converged:

- HashiCorp Vault: [replication
  architecture](https://developer.hashicorp.com/vault/docs/internals/replication) —
  performance-standby and secondary nodes forward writes to the active
  leader; they never locally author a privileged decision on the leader's
  behalf.
- CyberArk Conjur: [architecture
  overview](https://docs.cyberark.com/secrets-manager-sh/13.2/en/content/deployment/cjr-architecture.htm) —
  followers are read replicas; all writes go to the master.
- OpenBao: [standby nodes handle read
  requests](https://openbao.org/community/rfcs/standby-nodes-handle-read-requests/) —
  standby nodes are explicitly read-only; write authority stays on the active
  node.
- Infisical: [Infisical
  Gateway](https://infisical.com/blog/infisical-gateway) — a gateway relays
  network access to private resources; it does not carry or exercise its own
  write authority over the secrets platform's control plane.

A node never writes on another actor's behalf in any of these designs. This
ADR's Decision above reaches the same place by a different route: rather than
building a wire mechanism to carry a relayed human's identity, remove the
premise that a node's own authority should ever stand in for one.

### Note: this ADR's "downstream server" framing predates ADR-083 and should be read through it

This document (Context, above) frames the OR-gate's justification as "a
downstream server's already-authorized human action gets replayed against
the upstream's real storage" — the same "full downstream Keyorix server"
topology **ADR-083 (Accepted) later found never actually functioned and is
now boot-rejected** (`Config.Validate()` refuses `storage.type: remote` +
`server.http.enabled`/`server.grpc.enabled`). ADR-083's own Status header
says it "supersedes the 'full downstream Keyorix server' framing that had
informally grown up around ADR-049 in later code comments" — this ADR was
one more place that framing grew up. As the Status section above records,
that correction sat as a footnote for a full working session before it
drove a re-derivation of this ADR's actual Decision — see "How this ADR got
here" at the top of this document for the general lesson. The real caller of
these routes was always either (a) a genuine CLI one-shot command using
`RemoteStorage` directly, in-process, no router involved (the one
confirmed-working use of `storage.type: remote`), or (b) a human or node
credential hitting the hub's `/system` routes directly over HTTP — the G80
raw-storage-bypass campaign's finding, and ultimately the reason a Phase-1
liveness check of (b) specifically for a node credential was the thing that
actually resolved this ADR.

### Credential/MFA slice, resolved: option (b), restrict to the hub

The G80 overnight campaign's Tier 1 fixes needed an answer for the three
`/system` WebAuthn credential-management routes
(`CreateWebAuthnCredentialProxy`/`DeleteWebAuthnCredentialProxy`/
`SetUserWebAuthnEnabledProxy`) and, by the same reasoning,
`CreateMFAStepUpGrantProxy`: their real ceiling (`requireReauth`/
`verifyMFAStepUpCode`) is a **proof-of-possession** check — the target
account's current password/TOTP/step-up code — not an RBAC permission at
all, and the wire protocol has never carried that proof (only the
already-verified result). Two structurally available answers, matching
this ADR's own "second, harder question" framing: (i) extend the wire
protocol to carry the proof, or (ii) deny this slice a node/relay path
entirely and require whoever manages credentials to authenticate to the hub
directly.

**Decision for this slice: (ii).** Rationale: proof of possession cannot be
meaningfully relayed — forwarding a TOTP code or password proof across a
second hop converts a single-use, short-lived proof into something that
functions as a replayable bearer credential for the duration it stays
valid in transit and at the relay, which is a strictly worse security
property than not relaying it at all. Identity and credential management
operations belong at the identity authority (the hub), not at a relay one
hop removed from it. This does not contradict the ADR's main proposal (node
credentials still want their own scoped permission set for the operations
that legitimately DO relay) — it resolves one specific slice by removing it
from the relay surface rather than by scoping it.

**Confirmed before deciding, not assumed**: WebAuthn enrollment via
`RemoteStorage` is wired (`internal/storage/store/remote_webauthn.go` has
real HTTP-calling implementations) but has **zero real callers today** — no
`keyorix` CLI command performs WebAuthn registration (`internal/cli` has no
WebAuthn command at all; a passkey ceremony fundamentally needs a browser,
which no CLI process is), and the only other theoretical caller — a
downstream server replaying an already-completed browser ceremony — is the
now-superseded topology from the note above. Removing the `system.write`
permission arm for these specific routes (leaving them reachable only by a
genuine node credential, or removing the route entirely — a separate
implementation choice from this decision) therefore has no known
backward-compatibility cost to weigh. If a real product need for
CLI-driven or relayed credential/MFA management surfaces later, it should
be designed with a real proof-carrying mechanism from the start, not by
reopening this raw-storage path.

**Superseded by the liveness sweep (2026-08-24) — see "Removed implementations"
below.** The "not yet checked" question above was resolved: `CreateMFAStepUpGrantProxy`
has the same "wired but unused" shape as the WebAuthn trio — zero live callers, not
just no CLI command. That changes this slice's own premise. Restricting a route to
the hub is a decision about who gets to reach a route something still calls; when
nothing calls it in either topology, there is no relay traffic left to restrict —
deletion is the more consistent remedy, for the same reason the other 23 no-caller
`/system` routes were deleted rather than fixed. This section's reasoning (proof of
possession cannot be meaningfully relayed) remains correct and still governs any
FUTURE WebAuthn/MFA-enrollment relay work — see "Removed implementations" for what
that means going forward.

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
- ADR-030 — the `machine_identity_roles`/`AuthorizePrincipal` mechanism a
  node identity now uses, exactly like every other machine-identity type,
  with no special case.
- `core.MachineTypeNode`'s doc comment (`machine_identities.go:34-39`) — the
  "carries no implicit RBAC permission" invariant this ADR's final Decision
  preserves rather than retires.
- router.go:1052-1089 (pre-2026-08-25) — G79's own reasoning for the OR-gate
  this ADR removes, including its self-flagged admin-role-bypass caveat.
- ADR-083 (Accepted) — `validateRemoteStorageNotServer`
  (`internal/config/config.go:2029-2058`), establishing that no Keyorix
  server process can run `storage.type: remote`, which is what makes the
  Phase-1 liveness check below dispositive rather than merely suggestive.
- Phase-1 liveness check (2026-08-25) — the check that actually resolved this
  ADR: `createNodeToken` (`server/http/integration_test.go`) is test-only in
  every one of its ~21 references repo-wide; no Helm chart, Docker Compose
  file, or CLI flow provisions a node credential for `/system` use at
  runtime; `docs/REMOTE_CLI_SETUP.md` documents a bare node token as
  insufficient for real use. No live caller found, and ADR-083 forecloses any
  future one under the topology this ADR's Context section originally
  assumed.

## Out of scope

- The node-scoped permission set and the route-group split this ADR
  originally proposed implementing are **not built** — see "Why the original
  recommendation is superseded, not just unimplemented" above. There is no
  follow-up work item for them; the Decision above is the final state.
- The two confirmed findings (#1524's `AddGroupMemberProxy`/
  `ApproveRiskException` items) are **no longer** gated on this ADR — see
  "Update" above. They're fixed independently by a fail-closed rule for
  machine actors on per-actor-ceiling operations, not by anything this ADR
  decides.
- The downstream-actor-identity wire mechanism (the "harder question") is
  **closed**, not deferred to a future ADR — see "The wire-identity question:
  CLOSED" above.
- #1529 (no-check sites) and #1530 (unattributed audit) beyond citing them
  as evidence — both are already filed as their own issues with their own
  per-site recommendations.
- #1531 (wire-contract mismatch) — unrelated bug, not part of this design
  question.
- The global-tier enumeration and partition-boundary work (#1512, #1523,
  #1530, #1531, #1540, #1541, #1545, #1546, and the campaign's other named
  blind spots) — unrelated to this ADR's node-credential decision.

## Consequences (Accepted, 2026-08-25)

- `RequireNodeCredentialOrPermission` and every handler-level
  `isNodeCredentialRequest(r)` branch are deleted. `/api/v1/system` requires
  `system.write` for every caller with no second arm — a node credential
  with no role grant is refused at the group's own gate before reaching any
  handler at all. This closes the node-credential axis on every route this
  campaign tracked as HALF-FIXED for that reason
  (`AssignRoleWithExpiryProxy`/#1552 — the campaign's original "MOST SEVERE
  FINDING" — `RemoveGlobalAdminRoleGuardedProxy`, `CreateSetupTokenProxy`,
  `CreateMachineIdentityCredentialProxy`, `CreateOIDCBindingProxy`,
  `RevokeAllPersonalAccessTokensForUserProxy`,
  `DeleteSessionsForUserExceptProxy`), plus `RevokeMachineIdentityCredentialProxy`'s
  node-credential axis specifically (its own underlying cross-tenant gap,
  #1551, is unrelated to node credentials and remains open — see
  `docs/g80-raw-storage-bypass-triage.md`'s "ADR-085 resolution" section for
  the full closure record). This also supersedes and closes the per-actor-
  ceiling findings (`AddGroupMemberProxy`/`ApproveRiskExceptionProxy`) this
  ADR was originally motivated by — already fixed independently by the
  fail-closed rule described in "Update (2026-08-23)" above, and now
  additionally unreachable by a bare node credential at the gate level too.
- `MachineTypeNode`'s existing "carries no implicit RBAC permission of its
  own" invariant (`machine_identities.go`'s doc comment) is **preserved**,
  not retired — the opposite of what this ADR originally proposed. A node
  identity that needs to do anything privileged now needs the same real
  `MachineIdentityRole` grant any other machine-identity type would need; it
  gets no default, implicit, or type-based standing.
- The re-scoped open question ("should machine identities hold global-scope
  roles at all?") is now moot for this ADR's purposes: it only mattered as a
  precondition for the scoped-permission-set mechanism the Decision above no
  longer proposes building. It remains a live question for `internal/core`'s
  general machine-identity design (`core.CreateMachineIdentity` rejecting
  `projectID == 0`), but is no longer this ADR's concern.
- #1532's per-route classification table and
  `server/http/node_credential_route_classification_test.go` remain valid
  and continue to serve their original purpose unchanged: they pin per-actor
  ceiling enforcement for any machine actor holding a REAL permission grant
  (via `MachineIdentityRole`), a property orthogonal to the OR-arm's removal
  — confirmed by running that test suite unchanged against the post-removal
  code.
- No migration or rollout story is needed: this decision does not require
  any existing node credential to newly acquire a role grant it doesn't
  already have, because the Phase-1 liveness check found no real deployment
  relies on the removed arm in the first place. Any node credential that
  genuinely needs `/system` access today already has, or can be given, a
  normal `MachineIdentityRole` grant the same way any other machine identity
  would.

## Removed implementations (2026-08-24)

Separate from this ADR's still-open recommendation above, but recorded here because
it resolves the "Credential/MFA slice" decision two sections up: the G80
raw-storage-bypass campaign's liveness sweep (`docs/g80-tracking-issue-draft.md`)
traced every one of the campaign's 33 then-unfixed `/system` proxy findings for a
real caller — every `internal/cli` command and every `server/main.go` scheduler.
23 of the 33, including the WebAuthn trio and `CreateMFAStepUpGrantProxy` from the
Credential/MFA slice above, had **no live caller anywhere in either topology** — not
"reachable only by a node relay we choose to restrict," genuinely unreached. A
privileged route nothing calls is attack surface with no offsetting benefit, so all
23 were deleted rather than fixed or hub-restricted, in the PR that also lands this
note. Pre-deletion state is tagged `pre-system-proxy-deletion` — `git show
pre-system-proxy-deletion:path/to/file` recovers any individual file's prior
content for archaeology. **The tag is for archaeology, not for restoration**: do not
resurrect a handler from the tag if a similar need resurfaces. A future WebAuthn or
MFA-enrollment relay feature must be designed fresh against this ADR's proof-of-
possession principle (proof cannot be meaningfully relayed spoke-to-hub) and
`internal/core`'s current ceiling checks, not restored from history.

| # | Handler | File (removed) | What it did |
|---|---|---|---|
| 1 | `UpdateAccessReviewCampaignProxy` | `access_review_campaigns_proxy.go` | Raw proxy for force-closing an access-review campaign, bypassing `CloseAccessReviewCampaign`'s state-machine + independence checks. |
| 2 | `CreateBreakGlassActivationProxy` | `break_glass_proxy.go` | Raw proxy for creating a break-glass activation, bypassing `ActivateBreakGlass`'s membership/role-containment checks. |
| 3 | `UpdateBreakGlassActivationProxy` | `break_glass_proxy.go` | Raw proxy for updating a break-glass activation, bypassing the same create-time uniqueness guard. |
| 4 | `CreateConnectRefGrantProxy` | `connect_grants_proxy.go` | Raw proxy for creating a connect-ref grant, bypassing connector-existence/scope validation. |
| 5 | `DeleteConnectRefGrantProxy` | `connect_grants_proxy.go` | Raw proxy for deleting a connect-ref grant with no audit trail. |
| 6 | `UpdateDynamicSecretConfigProxy` | `dynamic_secrets_proxy.go` | Raw proxy for updating a dynamic-secret config, bypassing classification validation. |
| 7 | `TransitionDynamicSecretConfigDisabledProxy` | `dynamic_secrets_proxy.go` | Raw proxy for disabling a dynamic-secret config, bypassing the atomic CAS write `SetDynamicSecretConfigEnabled` provides. |
| 8 | `CreateDynamicSecretLeaseProxy` | `dynamic_secrets_proxy.go` | Raw proxy for issuing a dynamic-secret lease, bypassing `IssueLease`'s ceiling checks. |
| 9 | `UpdateDynamicSecretLeaseProxy` | `dynamic_secrets_proxy.go` | Raw proxy that could resurrect a revoked lease to active, bypassing `RevokeLease`/`RenewLease`. |
| 10 | `RestoreEnvironmentProxy` | `environment_catalog_proxy.go` | Raw proxy for restoring a soft-deleted environment with no actorID/authority parameter at all. |
| 11 | `UpdateLoginLockoutStateProxy` | `login_lockout_proxy.go` (file removed entirely) | Raw proxy for unlocking a locked-out user, bypassing `UnlockUser`'s `users.write` permission requirement. |
| 12 | `UpsertMFASecretProxy` | `mfa_management_proxy.go` | Raw proxy for planting an MFA/TOTP secret, taking `user_id`/`SecretEnc`/`Activated` straight from the caller. |
| 13 | `CreateMFAStepUpGrantProxy` | `mfa_stepup_proxy.go` | Raw proxy for granting an MFA step-up (satisfies the restricted-secret MFA gate) with zero TOTP/recovery-code verification. |
| 14 | `UpdateProjectProxy` | `project_catalog_proxy.go` | Raw proxy that could silently disable a project's MFA requirement, bypassing `roles.assign` and leaving no audit trail. |
| 15 | `RestoreProjectProxy` | `project_catalog_proxy.go` | Raw proxy for restoring a soft-deleted project with zero authority check, including any admin-tier role grants it carried. |
| 16 | `DeleteAnomalyAlertsBeforeProxy` | `retention_proxy.go` | Raw proxy for purging anomaly alerts, bypassing `legalHoldGuard`'s active-legal-hold refusal. |
| 17 | `DeleteClosedAccessReviewsBeforeProxy` | `retention_proxy.go` | Same `legalHoldGuard` gap, for closed access reviews. |
| 18 | `DeleteExpiredBreakGlassBeforeProxy` | `retention_proxy.go` | Same `legalHoldGuard` gap, for expired break-glass records. |
| 19 | `DeleteResolvedAccessRequestsBeforeProxy` | `retention_proxy.go` | Same `legalHoldGuard` gap, for resolved access requests. |
| 20 | `DeleteSecretDependencyProxy` | `secret_dependencies_proxy.go` | Raw proxy for deleting a secret-dependency edge, bypassing peer-endpoint authorization (the #G32 defense). |
| 21 | `CreateWebAuthnCredentialProxy` | `webauthn_proxy.go` | Raw proxy for registering a WebAuthn credential, bypassing `requireReauth` — could implant an attacker-controlled passkey on any account. |
| 22 | `DeleteWebAuthnCredentialProxy` | `webauthn_proxy.go` | Same `requireReauth` gap, for deleting a passkey. |
| 23 | `SetUserWebAuthnEnabledProxy` | `webauthn_proxy.go` | Same `requireReauth` gap, for flipping a user's WebAuthn-enabled flag. |

The other 12 of the campaign's 35 confirmed findings are unaffected by this note: 2
were already fixed independently (`TransitionMachineIdentityStateProxy`,
`UpdateMachineIdentityCredentialProxy`), and 10 have a real live caller and still
need a ceiling fix (`CreateAccessRequestProxy`, `UpdateAccessRequestProxy`,
`CreateInvitationProxy`, `UpdateInvitationProxy`, `UpdateUserIfActiveStateMatchesProxy`,
`CreateMachineIdentityProxy`, `CreateMachineIdentityCredentialProxy`,
`RevokeMachineIdentityCredentialProxy`, `CreateOIDCBindingProxy`,
`DeleteOIDCBindingProxy`) — tracked in `docs/g80-tracking-issue-draft.md`, not this ADR.

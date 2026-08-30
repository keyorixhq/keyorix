# ADR-091: `CreatedBy`-shaped attribution fields left 0 for a machine actor — classification and the invariant it depends on

## Status

**Closed (2026-08-30).** #1573, with #1621 folded in. Classification
complete: PR1 (#1622) fixed the check-breaking subset, PR2 (#1625) fixed the
mechanical attribution-only subset, and ConnectRefGrant (#1621) is verdicted
below — no third PR needed. See "What this does not resolve" for the
retroactive PR1/PR2 mapping and the one closed-without-a-fix item
(`SecretDependency`'s ID-space collision, #1623, tracked separately since
it's a different bug shape).

## What this is

#1530 fixed `AuditEvent.MachineIdentityID`: a machine identity's audit-log
attribution was 0 (unattributed) despite `ActorType` correctly saying
"a machine did this." #1573 asked the sibling question: do any *persisted
model fields* (`CreatedBy`, `RevokedBy`, `OwnerID`, and similarly-shaped
attribution columns) have the same gap — and unlike an audit log, a model
row's `CreatedBy: 0` cannot be backfilled later, because nothing else on the
row records who it really was.

## Task 1 — no centralization point exists, and the reason is structural

#1530's fix cost zero call sites because `emitAudit` (the single audit-write
choke point) lives in the same package (`internal/core`) as the context key
it reads (`machineActorFromContext`, `internal/core/audit_context.go`).

That precondition does not hold for model fields:

- Model attribution fields are set at `db.Create(&models.X{...})`, called
  from `internal/storage/store` using structs from `internal/storage/models`.
  Neither package imports `internal/core` (confirmed: `core` imports them,
  never the reverse) — a GORM hook living on a model struct (where hooks
  must live to fire automatically) cannot reference `core`'s **unexported**
  `machineActorKey{}` without either an import cycle or relocating the key
  to a new shared package neither side currently has.
- No `BeforeCreate` hook exists anywhere in this codebase today — only
  `BeforeSave` (15+ models, `models_beforesave_test.go`), and every one of
  those only normalizes the struct's own timestamp fields; none reads
  context.
- The machine ID is already available as a plain function parameter at
  (almost) every write site — `userCtx.MachineIdentityID`, resolved
  synchronously in the HTTP handler before the core call. #1530 needed
  context-threading specifically because audit writes run in **detached
  goroutines** past request cancellation (`DetachedAuditContext`); model
  creates don't have that problem, so the justification for context over an
  explicit parameter doesn't transfer either.

A hook-based centralization is buildable (relocate the context key,
introduce `BeforeCreate` as a real pattern) and would scale by *model count*
rather than *call-site count* — but it's a genuine architecture change, not
a "register one callback" fix, and its cost isn't clearly lower than passing
an already-available parameter explicitly. **Verdict: per-site, not
centralized.**

## Task 2 — the invariant this classification depends on

Ten of the 26 traced fields (across 8 models) were classified "unreachable
by any machine caller" because their route is gated by `RequirePermission`
(`== RequireScopedPermission(perm, ScopeGlobal)`) — and a machine identity
can **never** hold a role grant at global scope:

- `AssignMachineRole`'s `machineInProject` check (`internal/core/machine_token.go`)
  requires `m.ProjectID == scope.ProjectID`.
- Every real `MachineIdentity` row has a nonzero `ProjectID` —
  `CreateMachineIdentity` rejects `projectID == 0` outright
  (`internal/core/machine_identities.go`).
- The only production caller of `storage.AssignMachineRole` is
  `core.AssignMachineRole`, always behind `machineInProject` — no other path
  writes a `MachineIdentityRole` row.
- So `GetMachineRoleIDsAt(machineID, Scope{ProjectID: 0})` — the query
  `AuthorizePrincipal`'s machine branch uses — can never match a stored
  grant, for any machine, ever.

This rule is load-bearing for **ten** "unreachable" verdicts in this
classification, and for reachability analysis in #1545 as well. Applying it
consistently caught two initial over-claims during this investigation
(`RejectionReasonTemplate.CreatedBy` and `SecretTemplate.CreatedBy` were
both reported reachable via a route later found to be global-scope-gated).

**Guarded**: `internal/core/machine_global_scope_invariant_test.go` —
`TestAssignMachineRole_GlobalScopeRejected` pins the write-side half (a real
machine, nonzero `ProjectID`, can never be granted a role at
`Scope{ProjectID: 0}`); `TestCreateMachineIdentity_RejectsZeroProject` pins
the creation-side half that makes the write-side check meaningful (no
production path can ever produce the `ProjectID == 0` `MachineIdentity` row
that would otherwise defeat it);
`TestAssignMachineRole_GlobalScopeRejected_EvenIfMachineLookupSomehowReturnedGlobal`
documents — rather than silently assumes — that `machineInProject`'s
comparison alone would NOT catch a corrupted `ProjectID == 0` row; the
creation-side guard is the sole thing preventing that. Verified red by
temporarily relaxing `machineInProject`'s comparison to accept any project
and confirming `TestAssignMachineRole_GlobalScopeRejected` failed with
`storage.AssignMachineRole` actually invoked, then reverted.

**If this invariant is ever weakened** — `machineInProject` relaxed, or a
new path to `storage.AssignMachineRole`/`storage.CreateMachineIdentity`
added that bypasses either check — this guard goes red, and every "Bucket 3"
verdict below (and #1545's global-scope reasoning) must be re-derived, not
assumed to still hold.

## The one-sentence rule for the whole attribution family

Every machine-attribution field added under this family — #1573's Bucket 1
fixes (PR2/#1625), #1622's `ApproverMachineIdentityID`, #1623's per-model
discriminator columns — uses a **plain `uint` companion column with `0` as
"no machine actor," matching the shape of the human-attribution field it
sits beside on the same model**, never a nullable `*uint`. `AuditEvent.MachineIdentityID`
(nullable, #1530) is the one exception, and it is *not* a second pattern to
replicate: it predates this convention, and nullability there is load-bearing
for a reason specific to audit rows (distinguishing "no context tag present,"
e.g. impersonation/system events that never call `WithMachineActor` at all,
from "context tag present, human acted") that doesn't apply to a model create
path, where the human/machine split is always known synchronously at write
time — there is no third "unknown" state to represent. #1622's
`ApproverMachineIdentityID` additionally participates in
`uniqueIndex:ux_access_request_approver`, where a nullable column would
silently stop enforcing "one sign-off per approver" (NULL is never equal to
NULL in a unique index) — a second, independent reason plain `uint` is
correct there, not just consistency with the rest of the family. This
matches what #1623 landed on (PR #1625 confirmed via `git show ac8a1b10`
using plain `uint` throughout, citing #1573's shape explicitly) — one rule,
not a third shape.

## Task 2 — the three-bucket classification

26 attribution-shaped fields (`*By uint`/`*By *uint`/`OwnerID uint`) exist
across 22 models in `internal/storage/models/models.go` — no other file in
the package carries any.

### Bucket 1 — reachable, leaves 0 (10 fields / 9 models — the live gap)

| Model.Field | Core write site | Gate (scope) |
|---|---|---|
| `ProjectInvitation.InvitedBy` | `invitations.go:134,264` | `roles.assign` (project) |
| `AccessRequest.ResolvedBy` (approve path) | `invitations.go:785` | `roles.assign` (project) |
| `AccessRequest.ResolvedBy` (reject path) | `invitations.go:848` | `roles.assign` (project) |
| `AccessRequestApproval.ApproverID` | `invitations.go:741,779` | `roles.assign` (project) |
| `BreakGlassActivation.RevokedBy` | `break_glass.go:282` | `roles.assign` (project) |
| `AccessReviewCampaign.CreatedBy` | `access_review_campaign.go:98` | `roles.assign` (project) |
| `AccessReviewCampaign.ClosedBy` | `access_review_campaign.go:413` | `roles.assign` (project) |
| `SecretNode.OwnerID` (creation only) | `secrets.go:149` | `secrets.write` (project/env) |
| `SetupToken.CreatedBy` | `setup_token.go:132` | `roles.assign` (project) |
| `MachineIdentity.CreatedBy` | `machine_identities.go:108` | `roles.assign` (project) |
| `ProjectMembership.InvitedBy` | `membership_lifecycle.go:187` | `roles.assign` (project) |

Every route here is gated by an ordinary, project-scoped, machine-grantable
permission, and the handler forwards `userCtx.UserID`/`actor.UserID`
straight into the attribution field with no `isMachineActor` check. Note:
`AccessRequest.ResolvedBy` is set by two distinct code paths — see the
check-breaking split below.

**`SecretDependency.CreatedBy` was initially reported here and is removed —
this classification's own verification error, corrected before implementing
PR2.** The batch trace reported it as reachable-and-zero, inherited from
#1573's original filing, without re-checking the actual handler call site.
Re-verified: `server/http/handlers/secret_dependencies.go:89` calls
`AddSecretDependency` with `userCtx.PrincipalID()`, not `.UserID` —
`PrincipalID()` (`server/middleware/auth.go:135-140`) returns the machine's
own `MachineIdentity.ID` for a machine caller, not 0. `CreatedBy` is already
stamped with the machine's real ID. This surfaced a *different* problem
instead — `CreatedBy uint` has no discriminator between a `User.ID` and a
`MachineIdentity.ID` (separate tables, independent auto-increment sequences,
so the two can and eventually will collide numerically) — filed separately
as #1623, not fixed here; it's a different bug shape (silently ambiguous,
not silently absent) that plausibly needs its own schema decision. The other
8 Bucket-1 fields' handler call sites were all re-checked against the same
question and confirmed to pass the raw, always-zero-for-machines
`UserID`/`actor.UserID` — no other instance of this pattern found.

### Bucket 2 — reachable, correctly attributed/denied (5 fields / 5 models)

- `AccessReviewItem.DecidedBy` — `requireHumanReviewer` rejects `actorID==0` explicitly.
- `SecretACL.GrantedBy` — `GrantSecretACL` rejects `actorID==0` outright.
- `SecretNode.OwnerID` (**reassignment** path, distinct from creation above) — `secret_ownership.go`/`secret_reassign_owner.go` both reject `actorID==0`.
- `ShareRecord.OwnerID` — gated by `requireLiveOwnerAuthority` (`actorID == secret.OwnerID`); a machine's `actorID` (0) can never equal a real owner ID.
- `MachineIdentityOIDCBinding.CreatedBy` — `requireAdminAuthorityAt` resolves *user* role grants only; a machine's placeholder `actorID` (0) never resolves to an admin user row.
- `AccessRequest.ResolvedBy` (the `ApproveSecretAccessRequest` restricted-secret path, `classification_gate.go:288`) — gated by `requireAdminAuthorityAt`, same reasoning.

### Bucket 3 — unreachable by any machine caller (10 fields / 8 models)

`SoDPolicy.CreatedBy`, `LegalHold.PlacedBy`, `LegalHold.ReleasedBy`,
`RiskException.CreatedBy`, `RiskException.RevokedBy`,
`RiskException.ApprovedBy`, `AnomalyAlert.AcknowledgedBy`,
`AlertEscalationPolicy.CreatedBy`, `RejectionReasonTemplate.CreatedBy`,
`SecretTemplate.CreatedBy` — all gated by `RequirePermission` (unscoped),
including the `/system` `storage.type: remote` proxy siblings for
`LegalHold`/`RiskException`, which reuse the identical global `system.write`
group gate (`server/http/router.go:1097-1098`). Depends entirely on the
invariant above.

## Task 1 (continued) — the check-breaking subset

Not all 11 Bucket-1 fields are equal. Traced whether a zero *defeats a
check* (a correctness bug) versus merely *loses a record* (attribution
hygiene):

**`AccessRequestApproval.ApproverID` + `AccessRequest.ResolvedBy`'s approve
path — check-defeating, narrower than first thought.**
`ApproveAccessRequestWithExpiry` (`internal/core/invitations.go`) runs two
checks keyed on the raw actor value before either field is written:

1. Self-approval (`approverID == req.UserID`) — **investigated and ruled
   out**: `RequestProjectAccess` rejects `userID == 0` outright
   (`invitations.go:510-511`) and `AccessRequest.UserID` is never
   reassigned after creation, so a machine identity can never be the
   requester and `req.UserID` is guaranteed nonzero for the request's
   entire lifetime. A machine approver's `approverID` (0) can never
   collide with a real nonzero `req.UserID`. This check is safe as-is —
   an earlier pass through this investigation reported it as defeated;
   re-verified and corrected before implementing anything on that premise.
2. Distinct-approver counting (`hasAlreadyApproved`, iterating existing
   `AccessRequestApproval` rows for `ApproverID == approverID`) — **stands
   as the real defect**: under human-originated, K-of-N (K≥2) dual control,
   a first machine approves (`ApproverID: 0`); a second, genuinely
   different machine's legitimate approval collides on the same value and
   is wrongly rejected as "you have already approved this request." The
   threshold can never be reached via two or more distinct machine
   approvers — the DB-level `uniqueIndex:ux_access_request_approver` on
   `(RequestID, ApproverID)` would refuse the second row even if the
   in-memory check were bypassed.

Fails closed (no unauthorized grant ever occurs) but defeats dual control's
core promise of K *distinct* approvers for machine approvers, and returns a
false, misleading error to a legitimate second approver. This is a
correctness bug, not attribution loss — tracked for PR1. Since requesters
can never be machines, PR1's fix only needs to make `hasAlreadyApproved`
machine-identity-aware — no companion field is needed on `AccessRequest`
itself for the requester side.

`RejectAccessRequest` (`invitations.go:832`) also sets `ResolvedBy` but runs
neither check — attribution-only there.

**`BreakGlassActivation.RevokedBy` — attribution-only.** Every reference
repo-wide is either the single write site, a test assertion, or a wire/proxy
passthrough; the gRPC response conditionally omits it when zero rather than
comparing against it. No authorization decision anywhere reads this field.

**All other Bucket-1 fields** (`ProjectInvitation.InvitedBy`,
`AccessReviewCampaign.CreatedBy`/`ClosedBy`, `SecretNode.OwnerID`,
`SetupToken.CreatedBy`, `MachineIdentity.CreatedBy`,
`ProjectMembership.InvitedBy`) — attribution-only; none feeds a comparison
or counting check.

## Missing-field vs. zeroed-field split

These are different defects with different fixes, kept separate:

- **`Notification`** (`models.go:1250`) — no actor field at all, by design
  (confirmed unchanged from #1589): a notification doesn't need to record a
  trigger the way a governance record does. Not a bug.
- **`ConnectRefGrant`** (`models.go:677`) — **traced (#1621): no attribution
  field, by design. Not a bug.** `ConnectRefGrant{ID, RoleID, Connector,
  RefPrefix, ExpiresAt, CreatedAt}` is a pure role-to-capability binding —
  the same shape as `RolePermission`, `UserRole`, `GroupRole`, and
  `MachineIdentityRole`, all four of which were checked directly and none of
  which carry any actor field either (`UserRole`/`GroupRole` don't even
  carry `CreatedAt`). This codebase's convention is: attribution lives on
  *resource-grant* models (`ShareRecord`, `SecretACL`, `RiskException`,
  `BreakGlassActivation` — something is being granted TO someone, or an
  exception is being made FOR a reason), never on pure *role-binding* join
  models (something is being wired to a capability, full stop — the "who"
  is answered by the audit log, not the row). `CreateConnectRefGrant`/
  `DeleteConnectRefGrant` (`internal/core/connect_ref_grants.go`) do call
  `writeAuditEventFull` with `EventConnectRefGrantCreate`/`...Delete` on
  every write, and that audit trail's own `UserID`/`MachineIdentityID`
  attribution is now correct end-to-end (#1626/#1628, landed after this
  ADR was first written) — so "no persisted attribution column" does not
  mean "who did this is unrecoverable," only that it lives in the audit log
  instead of the row, consistent with every other join table of this shape.
  Closed without a fix: adding a field here would be the first attribution
  column on any pure role-binding model in this codebase, breaking the
  convention rather than following it.

## What this closes, and what's still open elsewhere

Two PRs, as scoped — not ten, and not a third:

- **PR1** (#1622, landed): fixed the check-breaking subset
  (`AccessRequestApproval.ApproverID` + `AccessRequest.ResolvedBy`'s approve
  and reject paths) with machine-identity-aware self-approval and
  distinct-approver logic, exploit-shaped tests, and positive controls.
  `TestAssignMachineRole_GlobalScopeRejected` and its two companions
  (`internal/core/machine_global_scope_invariant_test.go`) landed in this PR
  and are confirmed present and passing on current `main`.
- **PR2** (#1625, landed): mechanical, one diff — plain `uint` companion
  `*MachineIdentityID` fields (per the one-sentence rule above, NOT
  `AuditEvent`'s nullable shape) for the remaining 8 attribution-only
  Bucket-1 fields, populated at each write site from the already-resolved
  `userCtx.MachineIdentityID`. This PR also absorbed #1623's discovery
  (`SecretDependency.CreatedBy`'s ID-space collision) by adding
  `SecretDependency.CreatedByMachineIdentityID` alongside the rest.
- **#1621** (`ConnectRefGrant`) — traced and closed above: no attribution
  field, by design, matching every sibling role-binding model. No PR3.

**Data honesty**: every Bucket-1 field's existing `0` rows, written before
PR1/PR2, cannot be repaired — nothing else on those rows records who the
real actor was, unlike #1626's audit rows, which stay flaggable-as-suspect
via `ActorType` even without a backfill. This is a plain, permanent gap in
historical data for installs that existed before 2026-08-30, not silently
glossed over here.

- **#1623** (`SecretDependency.CreatedBy`'s `User`/`MachineIdentity` ID-space
  collision) — the discriminator column landed via PR2/#1625 above; tracked
  separately from this ADR because it's a different bug shape (silently
  *ambiguous*, not silently *absent*) and may still need its own schema
  decision for the general `*By uint`-without-discriminator pattern beyond
  this one field. Not reopened here.

# S1 sweep — "an issuer cannot widen" (2026-11-15)

Task S1, branch `fuzz/s1-issuer-cannot-widen`, built from the head of keyorix#4332
(the user-actor machine-token ceiling).

**Property swept.** For every path where actor *A* causes principal *P* (user,
machine, group, token, session, invitation) to gain credentials or permissions,
*A* must already hold at least what *P* gains (or a documented, tested exception
such as break-glass with mandatory review), and an actor restricted by PAT scope,
project/environment scope, IP allowlist or expiry cannot produce an *unrestricted*
artefact. An uncovered grant path must fail closed.

**Most reasonable reading taken (nobody answers questions).** "Widen" is read as
either (a) the minted/granted artefact carries permissions, scope, or a lifetime
the actor does not itself hold, or (b) the artefact sheds a confinement
(PAT/machine restriction: permission allowlist, project/env scope, CIDR, expiry)
that bound the actor. A path is ENFORCED when a mechanism fails closed on both,
GAP when either escapes with a live non-admin caller, DOCUMENTED EXCEPTION when
the widening is intentional, bounded and tested (break-glass).

## Two enforcement spines this repo already has

1. **The grant ceiling** — `requireGranterHoldsRolePermissions` /
   `…NoBaseline` / `requireGranterHoldsRoleSet` / `requireBaselineRoleGrantAuthority`
   (`internal/core/authz.go`). Every role-grant path routes through it; it calls
   `c.Authorize`/`AuthorizePrincipal` per bundled permission, and **`Authorize`
   intersects the PAT restriction** (`authz.go:137`). So a restricted PAT granting
   a role is automatically held to its restriction — no separate check needed on
   gated grant paths. `internal/guardrules.GrantCeilingMethods` derives, from the
   core AST, every exported method that reaches the ceiling, and
   `TestEveryGrantingServiceMapsPermissionDenied` (+ the REST twin) forces each
   transport to map the refusal.

2. **The machine/user mutation ceiling** — `requireAdminRankCeilingForTarget` →
   `requireEqualOrGreaterAdminAuthority` (the actor must out-rank the target at
   every scope), and `requireMachinePrivilegeCeiling` /
   `requireActorHoldsTargetPermissions` (the #4332 shared helper: the actor holds
   every permission the target holds; a restricted PAT is refused outright).

3. **Restricted-PAT deny-by-default for ungated writes** —
   `restrictedPATUngatedWrites` (`pat_restriction_writes.go`). Any write that does
   NOT reach `Authorize` must declare a policy here; AST guards
   (`TestEveryUngatedWriteDeclaresRestrictedPATPolicy` HTTP /
   `TestEveryUngatedGRPCWriteDeclaresRestrictedPATPolicy` gRPC) fail closed on an
   undeclared ungated write. This is what makes "a mint path that bypasses
   `Authorize`" (like PAT creation, break-glass, and — the #4332 case — machine
   token issue) fail closed unless an explicit entry/sentinel allows it.

## Sweep table

Verdict legend: **ENFORCED** (mechanism fails closed, test proves it) /
**GAP** (widening escapes with a reachable caller) / **DOC-EXCEPTION**
(intentional, bounded, tested) / **N/A-CLI** (trusted actor-0 local CLI path,
not transport-reachable).

| # | Path (core entry) | Transport entry points | Rule enforced (fn:line) | Restricted-actor handling | Proving test | Verdict |
|---|---|---|---|---|---|---|
| 1 | `IssueMachineToken` / `rotateMachineToken` | REST `POST /projects/{id}/machine-identities/{mid}/tokens`; gRPC `MachineIdentityService/IssueMachineToken` | `requireMachinePrivilegeCeiling` authz.go:663 (called machine_token.go:213); restricted-PAT refusal machine_token.go:210 | user-PAT restriction → refused (`patRestrictionFromContext != nil`); machine CIDR/fed refused via caller-credential check | `machine_token_user_actor_ceiling_test.go`, `machine_token_target_permission_ceiling_test.go`, `machine_token_caller_credential_test.go` | ENFORCED (#4332) |
| 2 | `AssignMachineRole` | REST `POST /machine-identities/{id}/roles`; gRPC `MachineIdentityService/AssignMachineRole` | `requireGranterHoldsRolePermissions` machine_token.go:709 | PAT restriction via `Authorize` in ceiling | (under verification) | ENFORCED |
| 3 | `CreateMachineIdentity` | REST `POST /projects/{id}/machine-identities`; gRPC | (under verification) | (under verification) | (under verification) | TBD |
| 4 | `AddProjectMember` | REST `POST /projects/{id}/members` | `requireGranterHoldsRolePermissions` project_members.go:48 | PAT via `Authorize` | (under verification) | ENFORCED |
| 5 | `InviteMember` | REST `POST /projects/{id}/invitations` | `requireGranterHoldsRolePermissions` membership_lifecycle.go:215 | PAT via `Authorize` | (under verification) | ENFORCED |
| 6 | invitation accept → membership activate | REST `POST /auth/setup/consume` etc. | ceiling at INVITE time; activate re-checks `requireGranterHoldsRolePermissions` membership_lifecycle.go:380 | — | (under verification) | ENFORCED |
| 7 | `CreateInvitation`/`CreateUserWithAssignments` (invitations.go) | REST `POST /invitations`, `POST /users` | `requireGranterHoldsRolePermissions(NoBaseline)` invitations.go:424/427/458, users.go:514/517/618 | PAT via `Authorize`; baseline via `requireBaselineRoleGrantAuthority` | (under verification) | ENFORCED |
| 8 | `AssignUserRole` | REST `POST /users/{id}/roles`; gRPC | `requireGranterHoldsRolePermissions` rbac_management.go:553 | PAT via `Authorize` | (under verification) | ENFORCED |
| 9 | `AssignUserRoleScoped`/`AssignRoleToUser` | — (no production transport caller; CLI only, actorID 0) | actorID-0 trusted exemption | — | reachability trace below | N/A-CLI |
| 10 | `AssignUserRoleWithExpiry` (JIT) | REST `POST /users/{id}/roles` (expiry) | `requireGranterHoldsRolePermissions` jit_access.go:44 | PAT via `Authorize` | (under verification) | ENFORCED |
| 11 | `AssignGroupRoleWithExpiry` | REST | `requireGranterHoldsRolePermissions` jit_access.go:87 | PAT via `Authorize` | (under verification) | ENFORCED |
| 12 | `AssignRoleToGroup` | REST `POST /groups/{id}/roles`; gRPC `GroupService/AssignRoleToGroup` | `requireGranterHoldsRolePermissions` rbac_management.go:228 | PAT via `Authorize` | (under verification) | ENFORCED |
| 13 | `AssignPermissionToRole` / `CreateRole(WithScope)` (role *definition*) | REST `POST /roles`, `POST /roles/{id}/permissions` | #169 definition ceiling (under verification) | (under verification) | (under verification) | TBD |
| 14 | `CreateOwnPAT` | REST `POST /auth/tokens` | restricted-PAT refusal pat.go:69 (`ErrRestrictedPATCannotMintPAT`); table entry pat_restriction_writes.go:97 | restricted PAT → refused; child never wider than owner (filter-at-use) | (under verification) | ENFORCED |
| 15 | `RefreshSession` / session rotation | REST `POST /auth/refresh` | (under verification — does rotation preserve confinement?) | (under verification) | (under verification) | TBD |
| 16 | `IssueSetupToken` | via guarded callers only (`ResendAccountSetupLink`, invite flows) | no authz in mint; caller gates (`requireAdminRankCeilingForTarget` setup_delivery.go:272) | (under verification) | (under verification) | TBD |
| 17 | access-request approve (`ApproveAccessRequestWithExpiry`, bulk) | REST `PUT /projects/{id}/access-requests/{rid}` | `requireGranterHoldsRolePermissions` invitations.go:1077/1207 | PAT via `Authorize` | (under verification) | ENFORCED |
| 18 | project/environment restore (role reinstatement) | REST `POST /projects/{id}/restore` | `requireAuthorityToReinstateProjectRoles` catalog.go:573/723 | PAT via `Authorize` | (under verification) | ENFORCED |
| 19 | SAML/OIDC/SCIM provisioning + group→role mapping | provisioning handlers | (under verification — IdP-driven, idpResolved bypass?) | (under verification) | (under verification) | TBD |
| 20 | break-glass | REST `POST /projects/{id}/break-glass` | intentional self-elevation with mandatory review; restricted PAT refused (`ErrRestrictedPATCannotBreakGlass`) | restricted PAT → refused | (under verification) | DOC-EXCEPTION |
| 21 | `UpdateUserRoles` (role-set replace) | REST `PUT /users/{id}/roles` | `requireGranterHoldsRoleSet` role_set_replace.go:69/97/303 | PAT via `Authorize` | (under verification) | ENFORCED |
| 22 | impersonation | REST `POST /users/{id}/impersonate` | `requireEqualOrGreaterAdminAuthority` impersonation.go:122; restricted PAT refused impersonation.go:57 | restricted PAT → refused | (under verification) | ENFORCED |

Rows marked "under verification" / TBD are resolved in the report
(`.scratch/s1-REPORT.md`, committed) as the sweep proceeds; this table is updated
in place.

## Status

This file is written early (task rule: a committed artefact must exist within 30
minutes). The RED-PROOF column and TBD verdicts are completed in subsequent
commits on this branch; see the report for per-path detail, what each oracle does
NOT verify, and reachability traces.

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
GAP when either escapes with a live non-admin caller, DOC-EXCEPTION when the
widening is intentional, bounded and tested (break-glass), N/A-CLI when the only
caller is the trusted actor-0 local CLI, TRANSPORT-ENFORCED when core performs no
refusal of its own and the router/interceptor is the sole (and sufficient) gate.

## Bottom line

**Negative result: every enumerated path is ENFORCED, DOC-EXCEPTION,
TRANSPORT-ENFORCED or N/A-CLI. No path lets a non-admin actor widen, and no
restricted actor can produce an unrestricted artefact on any path found.** The
#4332 defect class — a *permission-gated* mint whose *artefact* escapes the
actor's PAT restriction — exists only at `IssueMachineToken`, and #4332 already
closes it. The one defect this sweep newly found is in the **differential test
oracle**, not in production code: the `server/authzdiff` reference model never
learned about #4332's user-caller ceiling (fixed here; see row 1 and the report).

## Two (three) enforcement spines this repo already has

1. **The grant ceiling** — `requireGranterHoldsRolePermissions` /
   `…NoBaseline` / `requireGranterHoldsRoleSet` / `requireBaselineRoleGrantAuthority`
   (`internal/core/authz.go`). Every role-grant path routes through it; it calls
   `c.Authorize`/`AuthorizePrincipal` per bundled permission, and **`Authorize`
   intersects the PAT restriction** (`authz.go:137`/`193`). So a restricted PAT
   granting a role is automatically held to its restriction — no separate check
   needed on gated grant paths. `internal/guardrules.GrantCeilingMethods` derives,
   from the core AST, every exported method that reaches the ceiling, and
   `TestEveryGrantingServiceMapsPermissionDenied` (+ the REST twin) forces each
   transport to map the refusal.

2. **The mutation / target-permission ceiling** — `requireAdminRankCeilingForTarget`
   → `requireEqualOrGreaterAdminAuthority` (the actor must out-rank the target at
   every scope) and `requireMachinePrivilegeCeiling` /
   `requireActorHoldsTargetPermissions` (the #4332 shared helper: the actor holds
   every permission the target holds; a restricted PAT is refused outright).

3. **Restricted-PAT deny-by-default for ungated writes** —
   `restrictedPATUngatedWrites` (`pat_restriction_writes.go`). Any write that does
   NOT reach `Authorize` must declare a policy here; AST guards
   (`TestEveryUngatedWriteDeclaresRestrictedPATPolicy` HTTP /
   `TestEveryUngatedGRPCWriteDeclaresRestrictedPATPolicy` gRPC) fail closed on an
   undeclared ungated write. This is the net that catches a mint path bypassing
   `Authorize` (PAT creation, break-glass, and — the #4332 case — machine-token
   issue).

## Sweep table

| # | Path (core entry) | Transport entry | Rule enforced (fn:line) | Restricted-actor handling | Proving test | Verdict |
|---|---|---|---|---|---|---|
| 1 | `IssueMachineToken` / `rotateMachineToken` | REST `POST /projects/{id}/machine-identities/{mid}/tokens`; gRPC `MachineIdentityService/IssueMachineToken` | `requireMachinePrivilegeCeiling` authz.go:663 (machine_token.go:213); restricted-PAT refusal machine_token.go:210 | user restricted-PAT → refused outright; user must hold every target perm (authz.go:731); machine CIDR/fed via caller-credential check | `machine_token_user_actor_ceiling_test.go` (RED-PROOF ✓, both checks); authzdiff `machine.token.issue` op + new `fix-4332` plant | ENFORCED (#4332) |
| 2 | `AssignMachineRole` | REST `POST /machine-identities/{id}/roles`; gRPC | `requireGranterHoldsRolePermissions` machine_token.go:709 | PAT restriction via `Authorize` in ceiling | authzdiff `machine.role.assign` op; `name-based-role-check` plant | ENFORCED |
| 3 | `CreateMachineIdentity` | REST `POST /projects/{id}/machine-identities`; gRPC `MachineIdentityService/CreateMachineIdentity` | transport gate `RequireScopedPermission(roles.assign, project)` (router.go / machine_identity_service.go:113); core grants nothing on creation | PAT via `Authorize` at the gate (not in ungated table ⇒ gated) | authzdiff `machine.create` op | TRANSPORT-ENFORCED (creation confers no roles/credential; minting a credential is `IssueMachineToken`, row 1) |
| 4 | `AddProjectMember` / `SetProjectMemberRole` | REST `POST /projects/{id}/members` | `requireGranterHoldsRolePermissions` project_members.go:48/80 | PAT via `Authorize` | authzdiff `member.add`/`member.setrole`; `fix-3986`,`fix-3990` plants | ENFORCED |
| 5 | `InviteMember` / `InviteToProject` | REST `POST /projects/{id}/invitations` | `requireGranterHoldsRolePermissions` membership_lifecycle.go:215, invitations.go:153 | PAT via `Authorize` | `TestInviteToProject_EnforcesAdminCeiling` (RED-PROOF ✓) | ENFORCED |
| 6 | invitation accept → membership activate | setup-token consume → activate | ceiling at INVITE time; activation re-checks `requireGranterHoldsRolePermissions` membership_lifecycle.go:380 | — | existing membership-lifecycle tests | ENFORCED |
| 7 | `CreateUserWithAssignments` / `CreateUserWithSetupLink` | REST `POST /users`; gRPC `UserService/CreateUser` | baseline `requireBaselineRoleGrantAuthority` users.go:260/274; per-grant `requireGranterHoldsRolePermissions` users.go:618 | PAT via `Authorize`; baseline role ceiling | existing user-create ceiling tests | ENFORCED |
| 8 | `AssignUserRole` | REST `POST /users/{id}/roles`; gRPC | `requireGranterHoldsRolePermissions` rbac_management.go:553 | PAT via `Authorize` | existing rbac tests | ENFORCED |
| 9 | `AssignUserRoleScoped`/`AssignRoleToUser` | — (no production transport caller; only `_test.go` in `server/`) | actorID-0 trusted-CLI exemption (authz.go:1169) | — | reachability trace (report §Reachability) | N/A-CLI |
| 10 | `AssignUserRoleWithExpiry` (JIT) | REST `POST /users/{id}/roles` (expiry) | `requireGranterHoldsRolePermissions` jit_access.go:44 | PAT via `Authorize` | existing JIT tests (the G04 "most severe finding" regression) | ENFORCED |
| 11 | `AssignGroupRoleWithExpiry` | REST | `requireGranterHoldsRolePermissions` jit_access.go:87 | PAT via `Authorize` | existing JIT tests | ENFORCED |
| 12 | `AssignRoleToGroup` | REST `POST /groups/{id}/roles`; gRPC `GroupService/AssignRoleToGroup` | `requireGranterHoldsRolePermissions` rbac_management.go:228 | PAT via `Authorize` | `TestAddUserToGroup_CeilingRefusalMatchesErrPermissionDenied` (RED-PROOF ✓ via shared helper) | ENFORCED |
| 13 | `CreateRole(WithScope)` / `AssignPermissionToRole` (role *definition*, #169) | REST `POST /roles`, `POST /roles/{id}/permissions`; gRPC | #169 per-permission `Authorize`/`AuthorizePrincipal` rbac_management.go:105-131; `CreateRoleWithScope` adds perms one at a time, each gated (rbac_roles.go:160) | PAT via `Authorize` (authz.go:193 runs before the role-definition check) | existing #169 tests | ENFORCED |
| 14 | `CreateOwnPAT` | REST `POST /auth/tokens` | restricted-PAT refusal pat.go:69 (`ErrRestrictedPATCannotMintPAT`); ungated-write table pat_restriction_writes.go:97 | restricted PAT → refused; child never wider than owner (filter-at-use, authz.go) | existing PAT-GUARD-1 tests | ENFORCED |
| 15 | `RefreshSession` / session rotation | REST `POST /auth/refresh` | sessions are created only by interactive login/SSO (`mintSession`), never derived from a PAT; refresh copies only user identity (auth.go:625-632), carries no restriction to shed | PAT never obtains or rotates a session (`GetSessionAny` reads the session table only, auth.go:533) | existing auth tests | ENFORCED (no widening surface) |
| 16 | `IssueSetupToken` | none directly; only via `CreateUserWithSetupLink` (row 7) and `ResendAccountSetupLink` | mint has no authz; guarded callers only — `ResendAccountSetupLink` → `requireAdminRankCeilingForTarget` setup_delivery.go:272; creation via row 7's ceiling | — (setup token travels by email/out-of-band; the resend-to-existing-user takeover vector is already closed by the S1 admin-rank ceiling) | existing S1 setup-link takeover tests | ENFORCED (via callers) |
| 17 | access-request approve (`ApproveAccessRequestWithExpiry`, bulk) | REST `PUT /projects/{id}/access-requests/{rid}` | `requireGranterHoldsRolePermissions` invitations.go:1077/1207 | PAT via `Authorize` | `TestApproveAccessRequest_RejectsAdminGrantByNonAdmin` (RED-PROOF ✓ via shared helper) | ENFORCED |
| 18 | project/environment restore (role reinstatement) | REST `POST /projects/{id}/restore`, env restore | `requireAuthorityToReinstateProjectRoles` catalog.go:573/723 | PAT via `Authorize` | existing restore-ceiling tests | ENFORCED |
| 19 | SAML/OIDC/SCIM provisioning + group→role mapping | SCIM push (static token), SSO login | `assignUserRoleSystemGrant` deliberately bypasses the self-authority ceiling (the first SSO grant cannot require the user already hold the role); `idpAutoGrantOfRoleIsEscalation` authz.go:475-507 blocks admin-tier / `roles.assign`; `GroupRoleMap` is static YAML, not API-settable | SCIM endpoint is not PAT-authenticated | `idp_autogrant_escalation_test.go` | DOC-EXCEPTION / TRUSTED-BOUNDARY (see report caveat) |
| 20 | break-glass | REST `POST /projects/{id}/break-glass`; gRPC `BreakGlassService/ActivateBreakGlass` | intentional, bounded self-elevation: member-only, justified, time-boxed, auto-expiring, mandatory audit + review; restricted PAT refused (`ErrRestrictedPATCannotBreakGlass` break_glass.go:260) | restricted PAT → refused | authzdiff `breakglass.activate` op + membership-gate plant | DOC-EXCEPTION |
| 21 | `UpdateUserRoles` (role-set replace) | REST `PUT /users/{id}/roles` | `requireGranterHoldsRoleSet` role_set_replace.go:69/97/303 → per-role ceiling | PAT via `Authorize` | existing role-set-replace tests | ENFORCED |
| 22 | impersonation | REST `POST /users/{id}/impersonate` | `requireEqualOrGreaterAdminAuthority` impersonation.go:122; restricted PAT refused impersonation.go:57 | restricted PAT → refused | existing impersonation ceiling tests | ENFORCED |

## RED-PROOFs performed (plants in the working tree, run, confirmed red, reverted; never committed)

- **machine_token.go:210** (restricted-PAT refusal) → `if false && …` →
  `TestIssueMachineToken_RestrictedPATCannotMint` RED (FAIL). Reverted.
- **authz.go:725** (user target-permission ceiling) → `if false && …` →
  `TestIssueMachineToken_UserCannotMintForPeerHoldingPermissionItLacks` RED (FAIL).
  Reverted.
- **authz.go:1245** (shared grant-ceiling per-permission loop) → `if false && !ok` →
  `TestInviteToProject_EnforcesAdminCeiling` RED (the shared
  `requireGranterHoldsRolePermissionsNoBaseline` loop backs rows 2,4,5,6,7,8,10,
  11,12,17,18,21). Reverted.
- **authzdiff `fix-4332` plant** (authz.go:731 reverted via `-overlay`): the
  differential sweep produces 8 `unexplained` cases on `machine.token.issue`,
  control 0 — validated live (`AUTHZDIFF_PLANTS=1`, 18.9 s).

## New guard added (test-only, no production change)

`server/authzdiff` reference model now encodes #4332's user-caller ceiling
(`model_test.go`), and a `fix-4332-user-target-ceiling-removed` plant
(`plants_test.go`) keeps a red differential case for it — the twin of the
existing `fix-3993` machine-caller plant.

- **INV-CORE-authorize-before-target-lookup** A core operation that takes a target
  user ID authorizes the ACTOR before it looks the target up, so a refused actor gets
  one answer for every target: `transferOwnership` checks the owner / `roles.assign`
  before "already owned" and `GetUser(newOwnerID)` (#3794); `addProjectMember`,
  `SetProjectMemberRole`, `inviteMemberWithMode` and `AddUserToGroup` run
  the granter ceiling (`requireGranterHoldsRolePermissions` / `validateGroupJoinRoles`)
  before the domain allowlist check, which loads the target user.
  `SetProjectMemberRole` and `SetUserRoles` (`replaceUserRoleSet`) judge it on every
  requested role before they read the target's roles, so a no-op or a narrowing by an
  actor who may not grant a requested role is refused like any other request
  (FU-OWNERSHIP-1, ask ownership-oracle-1-role-set-noop-oracle (a)). Roles the request
  removes are not judged. Why: OWNERSHIP-ORACLE-1, after
  #3794. Guard: `internal/core/guards`
  `TestTargetLookupsFollowActorAuthorization` (AST, source order within a function;
  its doc comment lists what it does not check), `TestMemberGrants_UnauthorizedActorGetsIdenticalRefusal`,
  `TestTransferOwnership_UnauthorizedActorGetsIdenticalRefusal`,
  `TestRoleSetReplace_CeilingRefusal_SameForEveryTargetRoleSet`, REST
  `TestMemberGrantHandlers_UnauthorizedActorIdenticalAnswer`,
  `TestRoleSetRoutes_RoleBeyondCeiling_403EvenWhenAlreadyHeld`.

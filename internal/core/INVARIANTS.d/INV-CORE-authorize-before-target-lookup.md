- **INV-CORE-authorize-before-target-lookup** A core operation that takes a target
  user ID authorizes the ACTOR before it looks the target up, so a refused actor gets
  one answer for every target: `transferOwnership` checks the owner / `roles.assign`
  before "already owned" and `GetUser(newOwnerID)` (#3794); `addProjectMember`,
  `SetProjectMemberRole` (new member), `inviteMemberWithMode` and `AddUserToGroup` run
  the granter ceiling (`requireGranterHoldsRolePermissions` / `validateGroupJoinRoles`)
  before the domain allowlist check, which loads the target user. Not covered: the
  "already holds exactly this role" no-op and removal-only paths of
  `SetProjectMemberRole` / `SetUserRoles`, whose ceiling depends on the target's
  current roles (NEEDS ANDREI, OWNERSHIP-ORACLE-1). Why: OWNERSHIP-ORACLE-1, after
  #3794. Guard: `internal/core/guards`
  `TestTargetLookupsFollowActorAuthorization` (AST, source order within a function;
  its doc comment lists what it does not check), `TestMemberGrants_UnauthorizedActorGetsIdenticalRefusal`,
  `TestTransferOwnership_UnauthorizedActorGetsIdenticalRefusal`, REST
  `TestMemberGrantHandlers_UnauthorizedActorIdenticalAnswer`.

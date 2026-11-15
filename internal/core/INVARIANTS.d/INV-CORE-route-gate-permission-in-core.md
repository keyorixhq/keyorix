- **INV-CORE-route-gate-permission-in-core** A core entry point behind a REST route group or gRPC
  method that checks a permission before calling it checks that permission itself, for the acting
  principal the transports tag on ctx (a machine identity when ctx carries `ActorTypeMachine`,
  else the human `actorID`; actorID 0 untagged is the system pseudo-actor, intended difference
  ID-1), through one primitive `requireActorPermissions` and one gate per family
  (`internal/core/route_gate.go`): per-secret secrets.write `requireSecretGate` (ACL, role or an
  allowlisted share; ownership alone does not satisfy it) on auto-rotate, rotate, rollback, move,
  tags and description; secrets.write on the copy target (`CopySecret`); secrets.write at the
  shared secret's scope `requireSecretScopeGate` (`RevokeShare`); `requireEnvironmentCopyGate`
  (`CloneEnvironment`, `CopyEnvironmentSecrets`); `requireRoleAdminGate` plus
  `requireActorHoldsRolePermissions` (`UpdateRole`, `DeleteRole`, `AssignPermissionToRole`);
  `requireUserAdminGate` plus roles.assign per assignment (`CreateUserAudited`,
  `CreateUserWithAssignments`); `requireIdentityGrantGate` (`RestoreGroup`, `AssignRoleToGroup`,
  `AssignGroupRoleWithExpiry`, `AddUserToGroup`, `SetUserRoles`); `requireProjectRestoreGate`;
  `requireGlobalInvitationGate` (`InviteGlobal`, `InviteGlobalWithLink`); `requireBulkApprovalGate`.
  A refusal is typed `ErrPermissionDenied`, a failed lookup a storage read fault. The transport
  gates stay (defence in depth). Why: #4161 (authzdiff known-04: core allowed what both
  transports refuse on 22 ops). Guard: `server/authzdiff/core_route_gate_test.go`
  (`TestCoreEnforcesRouteGate` over every core-enforced mutating op whose REST route lies in one
  of the nine families, derived from the bound ops, red on main for all 22;
  `TestRouteGateFamiliesCoverKnownOps`) and the strict authzdiff sweep (no known-04 waiver).
  **Not covered**: ops whose core method does no authz at all (matrix `core refusal` none, ID-2),
  routes outside the nine families, and a core entry point the harness does not bind.

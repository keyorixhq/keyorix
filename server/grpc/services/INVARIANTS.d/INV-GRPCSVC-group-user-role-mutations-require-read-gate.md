- **INV-GRPCSVC-group-user-role-mutations-require-read-gate** `GroupGRPCService`'s
  `CreateGroup`/`UpdateGroup`/`DeleteGroup`/`RestoreGroup`/`RemoveGroupMember`,
  `UserGRPCService`'s `CreateUser`/`UpdateUser`/`ReissueOneTimePassword`/`DeleteUser`,
  and `RoleGRPCService`'s `CreateRole`/`UpdateRole`/`DeleteRole` each gate through
  `authorizeGlobalMutation(ctx, cs, actor, <read-perm>, <write-perm>)`
  (`conversions.go`), never `authorizeGlobal(ctx, cs, actor, <write-perm>)` alone —
  the write permission by itself is not sufficient, even though it was before this
  fix. This mirrors HTTP's `/groups`, `/users` and `/roles` route groups, each gated
  by an outer `r.Use(RequirePermission(<read>))` on the whole group plus a per-route
  `RequirePermission(<write>)` on the mutating ones (`server/http/router.go`): a
  principal holding only the write/delete/assign permission — never granted the
  group's own read permission — could mutate groups/users/roles over gRPC in cases
  REST would deny. `GroupGRPCService.AddGroupMember` is deliberately NOT covered by
  this invariant: the authzdiff harness's generated-permission sweep (known-01) does
  not flag it, and it is already covered separately by
  INV-GRPCSVC-04's machine-ceiling check. Why: authzdiff cross-layer differential
  harness waiver known-01 (`server/authzdiff/REPORT.md`, historical name D1).
  Guard: `authzdiff_known01_read_gate_test.go`
  (`TestGroupService_DeleteGroup_RequiresUsersRead`,
  `TestUserService_UpdateUser_RequiresUsersRead`,
  `TestRoleService_DeleteRole_RequiresRolesRead`),
  `group_service_test.go:TestGroupService_RestoreGroup_RequiresRolesAssign`,
  `role_service_test.go:TestRoleService_CreateRole_CannotClaimReservedAdminBypassName`,
  `user_service_test.go:TestUserService_CreateUser_RoleGrantRequiresAssign`.

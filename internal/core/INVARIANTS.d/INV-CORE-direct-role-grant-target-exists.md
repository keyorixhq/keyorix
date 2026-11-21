- **INV-CORE-direct-role-grant-target-exists** `AssignUserRole` and `AssignUserRoleWithExpiry`
  (REST `POST /user-roles`, both forms, and every other caller of the two) refuse a grant to a
  user id with no user row, with the user-not-found refusal (`storage.ErrUserNotFound`, REST 404),
  and write no grant and no `role.assigned` row. The granter ceiling is judged FIRST
  (`requireGrantTargetUser`), so an actor who may not grant the role gets the ceiling refusal for
  an absent and an existing target alike and learns nothing about which ids exist
  (OWNERSHIP-ORACLE-1). A fault reading the target is `ErrStorageReadUnavailable`, never "user not
  found". Why: `user_roles` has no foreign key, so the grant used to commit, with its audit row,
  for nobody. Guard: `TestAssignRole_AbsentTargetUser` (server/http/handlers). **Not covered**:
  the paths that reach `assignUserRole` without going through the two public methods
  (`AddProjectMember`, membership activation, access-request approval, `SetUserRoles`) do not
  read the target and were not changed; how the gRPC `AssignRole` answers the new refusal was not
  checked here (ERRMAP-GRPC-NOV-3 owns the gRPC mapping).

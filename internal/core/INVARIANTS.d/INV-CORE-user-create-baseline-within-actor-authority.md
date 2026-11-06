- **INV-CORE-user-create-baseline-within-actor-authority** Every user-creation
  path that knows its creating actor — `CreateUserAudited` (admin-set password),
  `CreateUserWithOneTimePassword`, `CreateUserWithSetupLink` and
  `CreateUserWithAssignments` — refuses an actor that does not hold every
  permission of the `system_viewer` baseline role the new user receives
  (`requireBaselineRoleGrantAuthority` / `requireGranterHoldsRolePermissionsNoBaseline`,
  without the `roles.assign` baseline). A machine actor is checked against its
  own permissions only when the transport tags it with `WithSelfMachineGranter`;
  both transports do on every creation path. A trusted internal caller (actor 0,
  not a machine) is exempt.
  Guard: `server/http/handlers/create_user_baseline_ceiling_test.go` `TestCreateUser_BaselineRoleCeiling`,
  `server/grpc/services/create_user_baseline_ceiling_test.go` `TestUserService_CreateUser_BaselineRoleCeiling`
  (each over all three creation paths).

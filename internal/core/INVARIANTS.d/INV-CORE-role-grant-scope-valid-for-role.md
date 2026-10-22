- **INV-CORE-role-grant-scope-valid-for-role** No role grant (user, group or machine identity)
  is written at a scope its role's `AssignableScope` does not allow: a `project` role
  (`project_*` built-ins, and every new custom role by default) never at the global scope
  (project 0), a `global` role (`system_*`, `alert_operator`) never at a project, and an
  environment scope always names its own project's environment (`{0, X}` and `{P, env of Q}`
  are refused). The role's stored scope decides (`models.EffectiveRoleAssignableScope`), never
  its name; built-in scopes come from one table (`models.BuiltinRoleAssignableScopes`), read by
  first-boot seeding and the one-time epoch-6 backfill (existing custom roles = `any`).
  Enforced in core at every storage grant write (`requireScopeValidForRole`,
  `role_scope_guard.go`), so every transport is covered; every handler/RPC that calls a core
  method able to return the refusal maps `ErrRoleScopeInvalid` to HTTP 400 / gRPC
  InvalidArgument. Widening a role's scope is fail-closed on the audit log like adding a
  permission. Grants written before #3546 are not changed; the startup notice
  (`server/wire_global_project_roles.go`) lists every grant outside its role's scope and every
  pending invitation that can no longer be accepted. Why: #3546 (DEMO-WALK-4: a group grant of
  project_developer with no project_id applied in every project).
  Guard: `role_scope_guard_registry_test.go` `TestEveryRoleGrantWriteChecksRoleScope` (AST:
  every function calling a storage grant writer calls the check or has a reasoned exemption;
  self-test `TestRoleScopeRegistryScanCatchesSyntheticShapes`), `role_scope_guard_test.go`
  `TestEveryRoleGrantEntryPointRefusesProjectRoleAtGlobalScope` (+ `_Postgres`; asserts no row
  written), `TestBuiltinRoleAssignableScopes_CoversEveryBuiltinRole`,
  `role_scope_reach_registry_test.go` `TestRoleScopeReachingMethodsFileIsCurrent` (derived
  reaching-method set) read by `server/http/handlers` `TestEveryRoleScopeReachingHandlerMapsTheRefusal`
  and `server/grpc/services` `TestEveryRoleScopeReachingRPCMapsTheRefusal`,
  `security_mutation_audit_role_scope_test.go`, `server/http/role_assignable_scope_http_test.go`.
  **Not covered**: a grant write outside internal/core is not scanned (transports reach storage
  only through core, see the registry test's header); the reaching-method derivation is
  name-based (it can over-include, never under-include, a method reached by a direct or method
  call; a call through a stored func value is not followed).

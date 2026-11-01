- **INV-STORE-scoped-grant-needs-live-scope-row** A role grant scoped to a project
  (`project_id != 0`) or an environment (`environment_id != 0`) authorizes only while that
  `projects` / `environments` row EXISTS and has `deleted_at IS NULL`. A grant whose row is
  gone (purged, or never there) applies nowhere; only `0` (global) needs no row. Every role
  reader applies the same predicate, `(<t>.project_id = 0 OR (<t>.project_id = ? AND
  projects.id IS NOT NULL AND projects.deleted_at IS NULL))` and its environment twin:
  `GetUserRoleIDsAt`, `GetUserGroupRoleIDsAt`, `GetMachineRoleIDsAt`, the single-statement
  `ResolveUserPermissionAt` / `ResolveMachinePermissionAt` (`local_principal_permission.go`),
  `ListUserRoleGrants` (`local_authz_batch.go`) and the machine value-read prefetch
  (`local_readpath_prefetch.go`). Why: THREATMODEL-VERIFY-1 / #2795 read side — the LEFT
  JOIN tested only `deleted_at IS NULL`, which is also true of the all-NULL row a missing
  project produces, so a purged project's leftover grants kept authorizing at that id.
  Guard: `scoped_grant_missing_scope_row_test.go` `TestScopedGrant_MissingScopeRowAuthorizesNothing`
  (every reader above, project row and environment row purged, SQLite and the pg leg, with a
  live-row positive control) and `TestReadPathPrefetch_MissingEnvironmentRowAuthorizesNothing`.
  Consequence for fixtures: a test that grants at project N must create project N
  (`seedLiveProjects` / `seedLiveEnv`). **Not covered**: a new role reader written with the
  old predicate is not caught structurally; `IsProjectMember` / `ProjectMembershipsAmong`
  (membership, not role resolution) do not join `projects`.

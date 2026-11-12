- **INV-CORE-admin-rank-ceiling-target-roles-one-read** `requireEqualOrGreaterAdminAuthority`
  (the admin-rank ceiling behind `requireAdminRankCeilingForTarget` and impersonation) takes
  the target's role set at every scope from ONE read, `ListUserRoleGrants` (one statement:
  direct and group grants, each with its scope and its role's ADR-084 bypass flag), and checks
  every scope that read lists a grant at plus every scope `GetUserRoleScopes` lists. It never
  lists the target's scopes and then re-reads the role set per scope: a grant moved between
  those reads (remove at project A, add at project B, one commit by another administrator) was
  discovered at A and found absent there, so an actor who does not outrank the target passed.
  Without a concurrent write the verdict is the old one; `GetUserRoleScopes` stays in the scope
  set because it also lists scopes of grants on a deleted project or environment, where the old
  per-scope read still applied the target's other grants. A fault on either read fails closed
  as a resolution failure (INV-CORE-04). Why: #4025. Guard:
  `admin_rank_ceiling_snapshot_test.go` (`TestAdminRankCeiling_ConcurrentScopeMoveSeenWhole`,
  SQLite and `_Postgres` with the move committed through a second connection pool: red before
  #4025; `TestAdminRankCeiling_SnapshotVerdictUnchanged`, the new check against the pre-#4025
  algorithm over a table of target and actor role shapes;
  `TestAdminRankCeiling_SnapshotReadFaultFailsClosed`). **Not covered**: the ACTOR's side is
  still read per scope (`scopedRoleIDs`, `Authorize`), so an actor demoted during the check can
  be judged on its earlier roles, the same check-then-act window as any authorization decision;
  the target's role-to-permission bundles (`rolePermissionNameSet`) are read per role after the
  snapshot, so an edit to a role's permissions during the check is seen per role.

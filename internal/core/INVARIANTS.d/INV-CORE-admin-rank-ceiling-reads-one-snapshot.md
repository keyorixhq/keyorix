- **INV-CORE-admin-rank-ceiling-reads-one-snapshot** `requireEqualOrGreaterAdminAuthority` (the admin-rank
  ceiling behind impersonation and every `requireAdminRankCeilingForTarget` caller) reads the target's roles at
  EVERY scope with one statement, `GetUserScopedRoleSets`, and evaluates every scope from that one result. It
  never reads the scope list and then each scope separately: those reads see different moments, so a grant
  another administrator moved between two scopes during the evaluation was seen at neither and the target looked
  as if it held nothing there (#4025). `ComposeUserScopedRoleSets` is the per-statement reference the
  one-statement read is tested against, and what a Storage wrapper that overrides one of its feeding reads
  forwards to. Why: #4025. Guard: `internal/core/admin_rank_ceiling_snapshot_test.go:TestAdminRankCeiling_GrantMovedDuringTheCheckIsStillSeen`
  (a gorm-level barrier moves the grant after the first target-grant statement; the check must refuse and must
  have read the target's grants in exactly one statement), `internal/storage/store/local_user_scoped_role_sets_test.go:TestGetUserScopedRoleSets_EquivalentToThePerStatementReads`
  (SQLite, and Postgres when `KEYORIX_TEST_PG_DSN` is set), `TestGetUserScopedRoleSets_IsOneStatement`,
  `internal/core/guards` `TestRoleReadWrappersForwardTheCombinedRoleRead` (a wrapper overriding a feeding read
  must forward the combined read).

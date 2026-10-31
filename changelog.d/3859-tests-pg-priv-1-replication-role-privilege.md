### Testing
- **Postgres tests that set `session_replication_role` skip on a role that may not, and fail in CI.**
  `internal/testutil/pgpriv.RequireReplicationRolePrivilege` probes the connected role once and
  skips (naming the missing privilege) unless `CI=true` or `KEYORIX_REQUIRE_PG_SUPERUSER=1`, where
  it fails. Ten tests use it, and `TestEveryReplicationRoleTestRequiresThePrivilege` (report-only
  rollout row) flags a test file that sets the role without calling it. Test-only change.

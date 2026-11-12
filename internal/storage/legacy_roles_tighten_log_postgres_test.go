package storage

// legacy_roles_tighten_log_postgres_test.go — the real-Postgres counterpart of
// TestLegacyRolesTighten_LogsOnceOnSQLite (pg-gated: KEYORIX_TEST_PG_DSN).

import "testing"

func TestLegacyRolesTighten_LogsOnce_Postgres(t *testing.T) {
	db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, pgTestDSN(t)))
	requireTightenLogOnce(t, db)
}

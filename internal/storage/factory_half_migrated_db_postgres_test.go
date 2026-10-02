// factory_half_migrated_db_postgres_test.go — the real-Postgres counterpart
// to factory_half_migrated_db_test.go's SQLite proof. Gated on
// KEYORIX_TEST_PG_DSN so `go test ./...` still passes cleanly with no
// Postgres available.
package storage

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

func TestHalfMigratedDB_Postgres_FromBeforeTransactionFix_NextBootFinishesIt(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	base := pgTestDSN(t)
	dsn := pgIsolatedDatabaseDSN(t, base)

	db := pgRawOpen(t, dsn)
	require.NoError(t, db.AutoMigrate(&models.Project{}))

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))

	for _, table := range []string{
		"projects", "environments", "users", "roles", "permissions",
		"role_permissions", "user_roles", "groups", "user_groups", "group_roles",
		"secret_nodes", "secret_versions", "share_records", "sessions", "tags",
		"secret_tags", "audit_events", "system_metadata", "anomaly_alerts",
		"anomaly_config_records", "stats_snapshots", "deployment_stats_snapshots",
		"mfa_step_up_grants",
	} {
		if !tableExists(db, table) {
			t.Fatalf("table %q still missing after migrateDatabase ran against a Postgres "+
				"database left half-migrated by a simulated pre-#2383 crash", table)
		}
	}
}

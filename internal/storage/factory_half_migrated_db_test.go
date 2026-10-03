// factory_half_migrated_db_test.go — coverage for a database left
// half-migrated by a crash that happened BEFORE #2383's transaction wrap
// existed. #2383 prevents any NEW crash during the fresh-install loop from
// leaving a half-migrated database (the whole tail now rolls back as one
// unit), but it cannot retroactively repair a database that was ALREADY left
// in that state by an older binary. This test constructs that historical
// artifact directly (bypassing migrateDatabase entirely, the same way a real
// crash under the OLD, non-transactional code would have left it) and
// verifies migrateDatabase now detects the incompleteness and finishes the
// migration, rather than treating "projects exists" alone as "fully
// migrated."
package storage

import (
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHalfMigratedDB_FromBeforeTransactionFix_NextBootFinishesIt is the red
// proof: construct a database with ONLY the projects table (and nothing
// else the fresh-install loop would have created), simulating exactly what a
// pre-#2383 crash right after the first model left behind, then run
// migrateDatabase and assert every fresh-install model's table exists
// afterward — not just that migrateDatabase returned nil.
func TestHalfMigratedDB_FromBeforeTransactionFix_NextBootFinishesIt(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	dbPath := filepath.Join(t.TempDir(), "half-migrated.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	// Construct the historical artifact directly: only models.Project's
	// table exists, exactly as the OLD non-transactional loop would have
	// left behind after a crash right after creating it and before creating
	// models.Environment (the loop's second entry).
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
			t.Fatalf("BUG: table %q still missing after migrateDatabase ran against a "+
				"database left half-migrated by a pre-existing (simulated pre-#2383) crash — "+
				"the boot check must verify every fresh-install model's table, not just "+
				"\"projects\", before deciding the database is already fully initialised", table)
		}
	}
}

// TestHalfMigratedDB_FullyMigrated_NoOpAndStillComplete is the green control:
// running migrateDatabase against an ALREADY fully-migrated database must
// still succeed and leave every table intact (freshInstallComplete must not
// cause a fully-migrated database to be wrongly re-processed in some
// destructive way — it's a no-op, but still exercised end to end).
func TestHalfMigratedDB_FullyMigrated_NoOpAndStillComplete(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	dbPath := filepath.Join(t.TempDir(), "fully-migrated.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))
	// Running it again against the now fully-migrated database must still succeed.
	require.NoError(t, f.migrateDatabase(db))

	assert.True(t, tableExists(db, "mfa_step_up_grants"))
}

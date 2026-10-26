package storage

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/require"
)

// TestAnomalyIndexes_Postgres_CreatedOnUpgrade is the Postgres twin of
// TestCompanionIndexes_CreatedOnUpgrade for the C-PERF-FIXES anomaly index (the secret_access_logs ones moved to the index build step: TestSecretAccessLogIndexes_*): a
// fresh install gets them from AutoMigrate's struct tags, and an install that
// predates them (simulated by dropping them) gains them on its next boot through
// migrateDatabase's CREATE INDEX IF NOT EXISTS block. A third boot proves the
// statements are idempotent on Postgres. Skips without KEYORIX_TEST_PG_DSN.
func TestAnomalyIndexes_Postgres_CreatedOnUpgrade(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, pgTestDSN(t)))
	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))

	indexes := []string{
		"idx_anomaly_alerts_dedup",
	}
	for _, idx := range indexes {
		require.True(t, indexExists(db, idx), "fresh install must have %s", idx)
		require.NoError(t, db.Exec("DROP INDEX "+idx).Error)
	}
	require.NoError(t, f.migrateDatabase(db))
	for _, idx := range indexes {
		require.True(t, indexExists(db, idx), "upgraded install must regain %s", idx)
	}
	require.NoError(t, f.migrateDatabase(db), "re-running the migration must be a no-op")
}

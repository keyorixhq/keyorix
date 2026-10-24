package storage

// factory_secret_access_log_indexes_test.go — the secret_access_logs indexes
// (store.SecretAccessLogIndexes*, PERF-INDEX-1) are created on fresh and upgraded
// databases, replace the three indexes earlier releases built, and on Postgres are
// built and dropped CONCURRENTLY (audit-list-keyset.md §4 applies unchanged).

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

var oldSecretAccessLogIndexes = map[string]string{
	"idx_secret_access_logs_secret_time":   "(secret_node_id, access_time)",
	"idx_secret_access_logs_access_time":   "(access_time, secret_node_id)",
	"idx_secret_access_logs_secret_action": "(secret_node_id, action)",
}

func seedAccessLogsRaw(t *testing.T, db *gorm.DB, n int) {
	t.Helper()
	for i := range n {
		require.NoError(t, db.Exec("INSERT INTO secret_access_logs (secret_node_id, secret_version_id, accessed_by, access_time, action) VALUES (?, 1, 'u', ?, 'read')",
			1+i%3, time.Now().UTC().Add(time.Duration(i)*time.Second)).Error)
	}
}

func installOldSecretAccessLogIndexes(t *testing.T, db *gorm.DB) {
	t.Helper()
	for name, cols := range oldSecretAccessLogIndexes {
		require.NoError(t, db.Exec("CREATE INDEX IF NOT EXISTS "+name+" ON secret_access_logs "+cols).Error)
	}
}

func TestSecretAccessLogIndexes_SQLite_FreshAndUpgrade(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "sal-idx.db"))
	require.NoError(t, err)
	f := &DefaultStorageFactory{}

	// Fresh install: the consolidated composite and the SQLite time btree exist,
	// none of the three replaced ones do.
	require.NoError(t, f.migrateSQLite(db))
	for _, ix := range store.SecretAccessLogIndexes {
		require.True(t, indexExists(db, ix.Name), "%s must exist", ix.Name)
	}
	require.True(t, indexExists(db, "idx_secret_access_logs_access_time"), "SQLite keeps the access_time btree")
	require.False(t, indexExists(db, "idx_secret_access_logs_access_time_brin"), "no BRIN on SQLite")
	for _, name := range store.SecretAccessLogReplacedIndexes {
		require.False(t, indexExists(db, name), "%s must not exist on a fresh install", name)
	}

	// Upgrade from a release with the three old indexes and data.
	for _, ix := range store.SecretAccessLogIndexes {
		require.NoError(t, db.Exec("DROP INDEX "+ix.Name).Error)
	}
	installOldSecretAccessLogIndexes(t, db)
	seedAccessLogsRaw(t, db, 20)

	require.NoError(t, f.migrateSQLite(db))
	for _, ix := range store.SecretAccessLogIndexes {
		require.True(t, indexExists(db, ix.Name), "%s must be built on upgrade", ix.Name)
	}
	for _, name := range store.SecretAccessLogReplacedIndexes {
		require.False(t, indexExists(db, name), "%s must be dropped on upgrade", name)
	}
	require.True(t, indexExists(db, "idx_secret_access_logs_access_time"))

	// Idempotent.
	require.NoError(t, f.migrateSQLite(db))
}

func TestSecretAccessLogIndexes_Postgres_UpgradeBuildsConcurrentlyAndDropsOld(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, pgTestDSN(t)))
	require.NoError(t, (&DefaultStorageFactory{}).migrateDatabase(db))
	sqlDB, err := db.DB()
	require.NoError(t, err)
	ctx := context.Background()

	// The state of an upgrade: the three old indexes, none of the new, data present.
	for _, ix := range append(append([]store.AuditListIndex{}, store.SecretAccessLogIndexes...), store.SecretAccessLogIndexesPostgres...) {
		require.NoError(t, db.Exec("DROP INDEX IF EXISTS "+ix.Name).Error)
	}
	installOldSecretAccessLogIndexes(t, db)
	seedAccessLogsRaw(t, db, 20)

	pending, err := store.AuditListIndexesPendingPostgres(ctx, sqlDB)
	require.NoError(t, err)
	require.True(t, pending)

	logs := &logCapture{}
	require.NoError(t, store.BuildAuditListIndexesPostgres(ctx, sqlDB, false, logs.logf))
	require.Contains(t, logs.joined(), "creating idx_secret_access_logs_secret_time_action CONCURRENTLY")

	for _, ix := range append(append([]store.AuditListIndex{}, store.SecretAccessLogIndexes...), store.SecretAccessLogIndexesPostgres...) {
		var def string
		require.NoError(t, db.Raw("SELECT indexdef FROM pg_indexes WHERE indexname = ?", ix.Name).Scan(&def).Error, ix.Name)
		require.NotEmpty(t, def, "%s must exist", ix.Name)
	}
	var brinDef string
	require.NoError(t, db.Raw("SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_secret_access_logs_access_time_brin'").Scan(&brinDef).Error)
	require.Contains(t, brinDef, "USING brin (access_time)")
	for name := range oldSecretAccessLogIndexes {
		require.False(t, indexExists(db, name), "%s must be dropped", name)
	}

	pending, err = store.AuditListIndexesPendingPostgres(ctx, sqlDB)
	require.NoError(t, err)
	require.False(t, pending)
	again := &logCapture{}
	require.NoError(t, store.BuildAuditListIndexesPostgres(ctx, sqlDB, false, again.logf))
	require.Empty(t, again.joined(), "a second build must issue no DDL")
}

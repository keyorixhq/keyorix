package storage

// factory_audit_list_indexes_test.go — the audit list indexes
// (store.AuditListIndexes) are created on fresh and upgraded databases, replace
// the single-column project_id / machine_identity_id indexes, and on Postgres
// are built CONCURRENTLY: idempotent, an INVALID leftover is rebuilt, and audit
// writes are never blocked (docs/specs/audit-list-keyset.md §4, §5.5).

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// ensureAuditListIndexesForTest runs the index step the factory runs after
// migrateDatabase, synchronously, on either dialect.
func ensureAuditListIndexesForTest(t *testing.T, db *gorm.DB) {
	t.Helper()
	if db.Dialector.Name() == "postgres" {
		sqlDB, err := db.DB()
		require.NoError(t, err)
		require.NoError(t, store.BuildAuditListIndexesPostgres(context.Background(), sqlDB, t.Logf))
		return
	}
	require.NoError(t, store.EnsureAuditListIndexesSQLite(db, t.Logf))
}

type logCapture struct {
	mu    sync.Mutex
	lines []string
}

func (c *logCapture) logf(format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprintf(format, args...))
}

func (c *logCapture) joined() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.lines, "\n")
}

// requireAuditListIndexesState asserts every composite exists and every
// replaced single-column index is gone.
func requireAuditListIndexesState(t *testing.T, db *gorm.DB) {
	t.Helper()
	for _, ix := range store.AuditListIndexes {
		require.True(t, indexExists(db, ix.Name), "%s must exist", ix.Name)
	}
	for _, name := range store.AuditListReplacedIndexes {
		require.False(t, indexExists(db, name), "%s is replaced by a composite and must be dropped", name)
	}
}

func insertAuditRowsRaw(t *testing.T, db *gorm.DB, n int) {
	t.Helper()
	for i := range n {
		require.NoError(t, db.Exec("INSERT INTO audit_events (event_type, project_id, machine_identity_id, event_time) VALUES (?, ?, ?, ?)",
			"secret.read", 1+i%3, 1+i%2, time.Now().UTC().Add(time.Duration(i)*time.Second)).Error)
	}
}

func TestAuditListIndexes_SQLite_FreshAndUpgrade(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "audit-list-idx.db"))
	require.NoError(t, err)
	f := &DefaultStorageFactory{}

	// Fresh install: the step the factory runs creates the composites, and
	// the model no longer creates the single-column indexes.
	require.NoError(t, f.migrateSQLite(db))
	requireAuditListIndexesState(t, db)

	// Upgrade from a release that had the single-column indexes and none of
	// the composites, with data in the table.
	for _, ix := range store.AuditListIndexes {
		require.NoError(t, db.Exec("DROP INDEX "+ix.Name).Error)
	}
	require.NoError(t, db.Exec("CREATE INDEX idx_audit_events_project_id ON audit_events (project_id)").Error)
	require.NoError(t, db.Exec("CREATE INDEX idx_audit_events_machine_identity_id ON audit_events (machine_identity_id)").Error)
	insertAuditRowsRaw(t, db, 20)

	logs := &logCapture{}
	require.NoError(t, f.migrateDatabase(db))
	require.NoError(t, store.EnsureAuditListIndexesSQLite(db, logs.logf))
	requireAuditListIndexesState(t, db)
	for _, ix := range store.AuditListIndexes {
		require.Contains(t, logs.joined(), "audit index build: creating "+ix.Name+" on audit_events (~20 rows)")
		require.Contains(t, logs.joined(), "audit index build: "+ix.Name+" done in ")
	}

	// Idempotent: nothing left to build, nothing logged.
	again := &logCapture{}
	require.NoError(t, store.EnsureAuditListIndexesSQLite(db, again.logf))
	require.Empty(t, again.joined())
}

// pgAuditListDB is an isolated Postgres database migrated by migrateDatabase
// only (no index step), with the audit list indexes removed and the two
// single-column indexes of earlier releases present: the state of an upgrade.
func pgAuditListDB(t *testing.T) *gorm.DB {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, pgTestDSN(t)))
	require.NoError(t, (&DefaultStorageFactory{}).migrateDatabase(db))
	for _, ix := range store.AuditListIndexes {
		require.NoError(t, db.Exec("DROP INDEX IF EXISTS "+ix.Name).Error)
	}
	require.NoError(t, db.Exec("CREATE INDEX IF NOT EXISTS idx_audit_events_project_id ON audit_events (project_id)").Error)
	require.NoError(t, db.Exec("CREATE INDEX IF NOT EXISTS idx_audit_events_machine_identity_id ON audit_events (machine_identity_id)").Error)
	insertAuditRowsRaw(t, db, 20)
	return db
}

func TestAuditListIndexes_Postgres_BuildIsIdempotentAndDropsReplaced(t *testing.T) {
	db := pgAuditListDB(t)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	ctx := context.Background()

	pending, err := store.AuditListIndexesPendingPostgres(ctx, sqlDB)
	require.NoError(t, err)
	require.True(t, pending)

	logs := &logCapture{}
	require.NoError(t, store.BuildAuditListIndexesPostgres(ctx, sqlDB, logs.logf))
	requireAuditListIndexesState(t, db)
	require.Contains(t, logs.joined(), "CONCURRENTLY")
	for _, ix := range store.AuditListIndexes {
		var def string
		require.NoError(t, db.Raw("SELECT indexdef FROM pg_indexes WHERE indexname = ?", ix.Name).Scan(&def).Error)
		require.Contains(t, def, "("+strings.Join(ix.Columns, ", ")+")", "%s definition", ix.Name)
	}

	pending, err = store.AuditListIndexesPendingPostgres(ctx, sqlDB)
	require.NoError(t, err)
	require.False(t, pending)
	again := &logCapture{}
	require.NoError(t, store.BuildAuditListIndexesPostgres(ctx, sqlDB, again.logf))
	require.Empty(t, again.joined(), "a second build must issue no DDL")
}

func TestAuditListIndexes_Postgres_InvalidIndexIsRebuilt(t *testing.T) {
	db := pgAuditListDB(t)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	ctx := context.Background()

	// An interrupted CREATE INDEX CONCURRENTLY leaves an INVALID index under
	// the name. Produce one the same way: a concurrent unique build that
	// fails on duplicates (every seeded row is secret.read).
	err = db.Exec("CREATE UNIQUE INDEX CONCURRENTLY idx_audit_events_event_time_id ON audit_events (event_type)").Error
	require.Error(t, err)
	var valid bool
	require.NoError(t, db.Raw(`SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
		WHERE c.relname = 'idx_audit_events_event_time_id'`).Scan(&valid).Error)
	require.False(t, valid, "fixture: the leftover must be INVALID")

	logs := &logCapture{}
	require.NoError(t, store.BuildAuditListIndexesPostgres(ctx, sqlDB, logs.logf))
	require.Contains(t, logs.joined(), "idx_audit_events_event_time_id is INVALID")
	var def string
	require.NoError(t, db.Raw("SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_audit_events_event_time_id'").Scan(&def).Error)
	require.Contains(t, def, "(event_time, id)")
	require.NotContains(t, def, "UNIQUE")
	pending, err := store.AuditListIndexesPendingPostgres(ctx, sqlDB)
	require.NoError(t, err)
	require.False(t, pending)
}

// TestAuditListIndexes_Postgres_BuildNeverBlocksAuditWrites is the red/green
// proof of "never block audit writes". A writer transaction stays open, so any
// index build has to wait for it. While the build waits, a second audit INSERT
// must complete. The control case shows that the harness does reproduce the
// hazard: a plain CREATE INDEX queues a SHARE lock behind the open writer, and
// the second INSERT queues behind that lock until the timeout.
func TestAuditListIndexes_Postgres_BuildNeverBlocksAuditWrites(t *testing.T) {
	run := func(t *testing.T, build func(ctx context.Context, db *gorm.DB) error) (insertErr error) {
		db := pgAuditListDB(t)
		ctx := context.Background()

		// The open writer: an uncommitted audit INSERT.
		holder := db.Begin()
		require.NoError(t, holder.Error)
		require.NoError(t, holder.Exec("INSERT INTO audit_events (event_type, event_time) VALUES ('secret.read', now())").Error)

		buildDone := make(chan error, 1)
		go func() { buildDone <- build(ctx, db) }()
		// Let the build reach its wait on the open writer.
		waitForLockWait(t, db)

		insCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		insertErr = db.WithContext(insCtx).Exec("INSERT INTO audit_events (event_type, event_time) VALUES ('secret.read', now())").Error

		require.NoError(t, holder.Commit().Error)
		require.NoError(t, <-buildDone)
		return insertErr
	}

	t.Run("CONCURRENTLY: the INSERT completes while the build waits", func(t *testing.T) {
		err := run(t, func(ctx context.Context, db *gorm.DB) error {
			sqlDB, err := db.DB()
			if err != nil {
				return err
			}
			return store.BuildAuditListIndexesPostgres(ctx, sqlDB, t.Logf)
		})
		require.NoError(t, err, "an audit INSERT must not wait for the index build")
	})

	t.Run("control: a plain CREATE INDEX blocks the INSERT", func(t *testing.T) {
		err := run(t, func(ctx context.Context, db *gorm.DB) error {
			return db.WithContext(ctx).Exec("CREATE INDEX idx_audit_events_event_time_id ON audit_events (event_time, id)").Error
		})
		require.Error(t, err, "harness check: a non-concurrent build must block the INSERT, or this test proves nothing")
	})
}

// waitForLockWait polls pg_stat_activity until some other session of this
// database is waiting on a lock (the index build waiting for the open writer).
func waitForLockWait(t *testing.T, db *gorm.DB) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var n int64
		require.NoError(t, db.Raw(`SELECT COUNT(*) FROM pg_stat_activity
			WHERE datname = current_database() AND pid <> pg_backend_pid() AND wait_event_type = 'Lock'`).Scan(&n).Error)
		if n > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the index build never started waiting on the open writer transaction")
}

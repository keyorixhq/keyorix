package core

// postgres_contention_helpers_test.go — shared setup for cross-replica
// Postgres HA-lock contention tests in this package. Distinct from
// TestConcurrency_BootstrapSystem_CrossReplicaExactlyOneAdmin's own
// sharedBootstrapStorage: that helper hands every simulated "replica" the
// SAME storage.Storage instance, so they all serialize through one shared
// LocalStorage's process-local bootstrapMu regardless of whether the
// Postgres advisory lock in WithBootstrapLock does anything at all — a
// single-instance test cannot distinguish "the lock works" from "the lock is
// gone". These helpers instead give each simulated replica its own *gorm.DB
// connection (own LocalStorage, own bootstrapMu) into the SAME isolated
// Postgres schema, so pg_advisory_lock is the only thing left that can still
// serialize them.

import (
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var corePgContentionSchemaCounter int64

// pgTestDSN returns the KEYORIX_TEST_PG_DSN base DSN, skipping the test (not
// failing it) when unset.
func pgTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — skipping Postgres HA-lock contention test")
	}
	return dsn
}

// pgIsolatedSchemaDSN creates a fresh schema on the real Postgres server at
// base, dropped on test cleanup, and returns a DSN with search_path pointed
// at it.
func pgIsolatedSchemaDSN(t *testing.T, base string) string {
	t.Helper()
	n := atomic.AddInt64(&corePgContentionSchemaCounter, 1)
	schema := fmt.Sprintf("core_contend_%d_%d", os.Getpid(), n)

	admin := pgOpen(t, base)
	require.NoError(t, admin.Exec("DROP SCHEMA IF EXISTS "+schema+" CASCADE").Error)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		cleaner := pgOpen(t, base)
		_ = cleaner.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
	})

	return base + " search_path=" + schema
}

// pgOpen opens a *gorm.DB against dsn, closing it on test cleanup. Each call
// is a genuinely separate connection — the independence contention tests in
// this file rely on.
func pgOpen(t *testing.T, dsn string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	t.Cleanup(func() {
		if sqlDB, dbErr := db.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
	})
	return db
}

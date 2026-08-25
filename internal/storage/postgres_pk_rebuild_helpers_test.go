package storage

// postgres_pk_rebuild_helpers_test.go — setup for exercising rolePKIsComplete/
// rebuildRolePKPostgres against a REAL Postgres server. Unlike the contention
// tests elsewhere in this campaign (internal/storage/store,
// internal/core), this one cannot use a search_path-scoped isolated SCHEMA:
// rolePKIsComplete, tableExists, and columnExists (factory.go) all hardcode
// `table_schema = 'public'` in their information_schema queries, so a table
// created under a non-public schema is invisible to them regardless of
// search_path. (That hardcoding is itself worth noting: a deployment using a
// non-default Postgres schema would have every one of these existence/PK
// checks silently return false-negative — out of this campaign's scope to
// fix, but recorded here since building this test is what surfaced it.)
// This file instead isolates by creating a fresh, disposable DATABASE per
// test, so each test's tables genuinely live in that database's own "public"
// schema.

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var pkRebuildDBCounter int64

// pgTestDSN returns the KEYORIX_TEST_PG_DSN base DSN, skipping the test (not
// failing it) when unset.
func pgTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — skipping Postgres role-PK migration test")
	}
	return dsn
}

// pgIsolatedDatabaseDSN creates a fresh, empty database on the real Postgres
// server at base, dropped on test cleanup, and returns a DSN pointing at it.
func pgIsolatedDatabaseDSN(t *testing.T, base string) string {
	t.Helper()
	n := atomic.AddInt64(&pkRebuildDBCounter, 1)
	dbName := fmt.Sprintf("pk_rebuild_%d_%d", os.Getpid(), n)

	admin := pgRawOpen(t, base)
	require.NoError(t, admin.Exec("CREATE DATABASE "+dbName).Error)
	t.Cleanup(func() {
		cleaner := pgRawOpen(t, base)
		// FORCE (PG 13+) drops even if something still holds a connection —
		// this test always closes its own connections first, but a failed
		// test run may not have.
		_ = cleaner.Exec("DROP DATABASE IF EXISTS " + dbName + " WITH (FORCE)").Error
	})

	return replaceDBName(base, dbName)
}

// replaceDBName swaps the dbname= field in a libpq-style "key=value ..." DSN.
func replaceDBName(dsn, newName string) string {
	fields := strings.Fields(dsn)
	out := make([]string, 0, len(fields)+1)
	found := false
	for _, f := range fields {
		if strings.HasPrefix(f, "dbname=") {
			out = append(out, "dbname="+newName)
			found = true
			continue
		}
		out = append(out, f)
	}
	if !found {
		out = append(out, "dbname="+newName)
	}
	return strings.Join(out, " ")
}

// pgRawOpen opens a *gorm.DB against dsn, closing it on test cleanup.
func pgRawOpen(t *testing.T, dsn string) *gorm.DB {
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

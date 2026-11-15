package sqllogicfuzz

import (
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	sqlitedialect "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

// pgPrefix is the mandatory database-name prefix for this task's PostgreSQL
// databases. IsolatedDatabase names them <prefix>_<pid>_<n>, and drops them on
// cleanup, so every database this harness creates starts with "sq1_".
const pgPrefix = "sq1"

var tableCounter atomic.Int64

func nextTable() string { return fmt.Sprintf("t_%d", tableCounter.Add(1)) }

// newSQLiteMem opens a fresh in-memory modernc-SQLite database (the production
// dialector) with a single connection, so the :memory: database persists for
// the handle's lifetime.
func newSQLiteMem(tb testing.TB) *gorm.DB {
	tb.Helper()
	db, err := gorm.Open(sqlitedialect.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		tb.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		tb.Fatalf("sqlite DB(): %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	tb.Cleanup(func() { _ = sqlDB.Close() })
	return db
}

// createTable creates the fixed schema under the given name for the given
// dialect.
func createTable(db *gorm.DB, name string, isPostgres bool) error {
	ddl := tableCreateSQLite
	if isPostgres {
		ddl = tableCreatePostgres
	}
	return db.Exec(fmt.Sprintf(ddl, name)).Error
}

// --- PostgreSQL, created once per process in TestMain, dropped at the end ---

var (
	pgDB *gorm.DB
	pgOK bool
)

// pgSetup returns the process-wide *gorm.DB on the "sq1_*" database created by
// TestMain, or (nil,false) when KEYORIX_TEST_PG_DSN is unset.
func pgSetup(tb testing.TB) (*gorm.DB, bool) {
	tb.Helper()
	return pgDB, pgOK
}

// TestMain owns the lifecycle of the PostgreSQL database for the whole package
// run (tests AND fuzz iterations). The database is created once, named
// "sq1_<pid>", and dropped on exit. Binding it to a single test's Cleanup would
// drop it before the fuzz loop runs, which is exactly the bug this avoids.
func TestMain(m *testing.M) {
	base := os.Getenv("KEYORIX_TEST_PG_DSN")
	var dbName string
	if base != "" {
		dbName = fmt.Sprintf("%s_%d", pgPrefix, os.Getpid())
		if err := pgAdminExec(base, "DROP DATABASE IF EXISTS "+quoteIdent(dbName)+" WITH (FORCE)"); err != nil {
			fmt.Fprintf(os.Stderr, "sq1: pre-drop %s: %v\n", dbName, err)
		}
		if err := pgAdminExec(base, "CREATE DATABASE "+quoteIdent(dbName)); err != nil {
			fmt.Fprintf(os.Stderr, "sq1: create %s (PG oracle disabled): %v\n", dbName, err)
		} else {
			dsn := pgdsn.PGReplaceDBName(base, dbName)
			db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
			if err != nil {
				fmt.Fprintf(os.Stderr, "sq1: open %s (PG oracle disabled): %v\n", dbName, err)
			} else {
				pgDB, pgOK = db, true
			}
		}
	}

	code := m.Run()

	if pgOK {
		if sqlDB, err := pgDB.DB(); err == nil {
			_ = sqlDB.Close()
		}
		if err := pgAdminExec(base, "DROP DATABASE IF EXISTS "+quoteIdent(dbName)+" WITH (FORCE)"); err != nil {
			fmt.Fprintf(os.Stderr, "sq1: drop %s: %v\n", dbName, err)
		}
	}
	os.Exit(code)
}

func quoteIdent(name string) string { return pgx.Identifier{name}.Sanitize() }

// pgAdminExec opens a short-lived admin connection to base and runs stmt
// (CREATE/DROP DATABASE cannot run inside the target database).
func pgAdminExec(base, stmt string) error {
	db, err := gorm.Open(postgres.Open(base), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return err
	}
	if sqlDB, err := db.DB(); err == nil {
		defer func() { _ = sqlDB.Close() }()
	}
	return db.Exec(stmt).Error
}

// dropTable best-effort drops a per-iteration table.
func dropTable(db *gorm.DB, name string) {
	_ = db.Exec("DROP TABLE IF EXISTS " + name).Error
}

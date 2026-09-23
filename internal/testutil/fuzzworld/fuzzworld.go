// Package fuzzworld is the shared DB-world helper for the repo's stateful,
// DB-touching fuzzers (#1962): a world is built ONCE per testing.F (before
// f.Fuzz) and reused across every iteration, with an explicit per-iteration
// table reset, against SQLite always and PostgreSQL too whenever
// KEYORIX_TEST_PG_DSN is set.
//
// It replaces four near-identical per-package copies that had started to
// drift risk (internal/core, internal/encryption and server/http
// fuzzworld_test.go, plus server/http/concurrent_linearizable_fuzz_test.go's
// own Postgres world). Only the genuinely shared mechanics live here:
//
//   - OpenSQLite: open a SQLite DB with a caller-chosen DSN / pool size —
//     callers differ deliberately (plain ":memory:" vs shared-cache WAL vs a
//     file DSN), so the DSN stays the caller's decision.
//   - OpenPostgres: schema-per-call isolation on the shared server, dropped
//     on cleanup; nil when KEYORIX_TEST_PG_DSN is unset.
//   - Worlds / World.Reset: the "SQLite + optional Postgres, migrated from a
//     model list, reset from an explicit table list" shape two packages use.
//
// Test-only: nothing outside *_test.go files may import this package.
package fuzzworld

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

// Backend names, used in World.Backend and in failure messages.
const (
	BackendSQLite   = "sqlite"
	BackendPostgres = "postgres"
)

// PGDSNEnv is the environment variable that opts a run into the PostgreSQL
// backend.
const PGDSNEnv = "KEYORIX_TEST_PG_DSN"

// World is a *gorm.DB built once per testing.F and reused across fuzz
// iterations; see Reset for restoring a clean state between iterations.
type World struct {
	Backend string // BackendSQLite or BackendPostgres
	DB      *gorm.DB
}

var pgSchemaSeq atomic.Int64

// OpenSQLite opens dsn with the SQLite dialect. maxOpenConns > 0 caps the
// pool (a plain ":memory:" DSN without cache=shared gives every pooled
// connection its own separate database, so callers relying on one shared DB
// pass 1); 0 leaves the pool at its default. Fails tb on error.
func OpenSQLite(tb testing.TB, dsn string, maxOpenConns int) *gorm.DB {
	tb.Helper()
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		tb.Fatalf("open sqlite: %v", err)
	}
	if maxOpenConns > 0 {
		if sqlDB, e := db.DB(); e == nil {
			sqlDB.SetMaxOpenConns(maxOpenConns)
		}
	}
	return db
}

// OpenPostgres returns nil (not a skip) when KEYORIX_TEST_PG_DSN is unset —
// the caller decides whether that's fine. Otherwise it creates a fresh schema
// named "<schemaPrefix>_<pid>_<seq>" (schemaPrefix keeps different fixtures
// sharing one server apart), drops it again on tb's cleanup, and returns a
// connection whose search_path points at it.
func OpenPostgres(tb testing.TB, schemaPrefix string) *gorm.DB {
	tb.Helper()
	dsn := os.Getenv(PGDSNEnv)
	if dsn == "" {
		return nil
	}
	n := pgSchemaSeq.Add(1)
	schema := fmt.Sprintf("%s_%d_%d", schemaPrefix, os.Getpid(), n)

	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		tb.Fatalf("open postgres (admin): %v", err)
	}
	if err := admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error; err != nil {
		tb.Fatalf("drop schema %s: %v", schema, err)
	}
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		tb.Fatalf("create schema %s: %v", schema, err)
	}
	tb.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if sqlDB, e := admin.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})

	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		tb.Fatalf("open postgres: %v", err)
	}
	return db
}

// Migrate AutoMigrates each model into w, one at a time so a failure names
// the offending model and backend.
func (w *World) Migrate(tb testing.TB, models []any) {
	tb.Helper()
	for _, m := range models {
		if e := w.DB.AutoMigrate(m); e != nil {
			tb.Fatalf("migrate %T (%s): %v", m, w.Backend, e)
		}
	}
}

// Worlds returns the SQLite world (always, opened on sqliteDSN with
// sqliteMaxOpenConns — see OpenSQLite) plus the PostgreSQL world (when
// KEYORIX_TEST_PG_DSN is set), each migrated with models. Callers range over
// the result, running one pass of the fuzz body per world.
func Worlds(tb testing.TB, schemaPrefix, sqliteDSN string, sqliteMaxOpenConns int, models []any) []*World {
	tb.Helper()
	sq := &World{Backend: BackendSQLite, DB: OpenSQLite(tb, sqliteDSN, sqliteMaxOpenConns)}
	sq.Migrate(tb, models)
	worlds := []*World{sq}
	if db := OpenPostgres(tb, schemaPrefix); db != nil {
		pg := &World{Backend: BackendPostgres, DB: db}
		pg.Migrate(tb, models)
		worlds = append(worlds, pg)
	} else {
		tb.Logf("%s not set (%s) -- PostgreSQL backend skipped, SQLite only", PGDSNEnv, schemaPrefix)
	}
	return worlds
}

// Reset restores w to an empty-but-migrated state between fuzz iterations,
// cheaply enough to run on every input. tables is an EXPLICIT, hand-named
// list (not derived from the migrated models, so a model added later can't
// silently escape the reset) in dependent-first order: Postgres
// TRUNCATE ... CASCADE doesn't need it, but SQLite's per-table DELETE does
// not resolve FK ordering on its own.
//
// Returns an error rather than taking a testing.TB so callers with no
// *testing.T in scope (e.g. a bare goroutine that reports by panicking) can
// adapt it to their own idiom.
func (w *World) Reset(tables []string) error {
	switch w.Backend {
	case BackendPostgres:
		stmt := "TRUNCATE TABLE " + strings.Join(tables, ", ") + " CASCADE"
		if err := w.DB.Exec(stmt).Error; err != nil {
			return fmt.Errorf("[postgres] reset tables %v: %w", tables, err)
		}
	default:
		for _, tbl := range tables {
			if err := w.DB.Exec("DELETE FROM " + tbl).Error; err != nil {
				return fmt.Errorf("[sqlite] delete from %s: %w", tbl, err)
			}
		}
	}
	return nil
}

//go:build !windows

package core

// fuzzworld_test.go -- shared DB-world helper for FuzzCoreOperationSequence.
//
// DELIBERATE DUPLICATION, not an oversight: two other near-identical copies
// of this exact pattern exist in this repo --
// internal/encryption/fuzzworld_test.go (FuzzDEKSweepCrashConsistency,
// FuzzFaultInjectedOperations) and server/http/fuzzworld_test.go
// (FuzzKeyorixHTTPAPISequence, FuzzMultiTenantIsolation). Go's unexported
// symbols don't cross package boundaries, and this repo's own existing
// precedent (server/http/concurrent_linearizable_fuzz_test.go's own local
// buildLinearizabilityWorldSQLite/buildLinearizabilityWorldPostgres)
// already duplicates this exact shape per-fuzzer rather than extracting a
// shared library. A tracking issue to extract a shared
// internal/testutil/fuzzworld package is filed once all three of these
// copies have landed -- see that issue for the extraction trigger
// ("the pattern has stopped changing"), not before.
//
// SQLite always runs (matching today's default -- no DSN, no behavior
// change). PostgreSQL additionally runs whenever KEYORIX_TEST_PG_DSN is
// set, via a schema-per-testing.F, gorm.Open(postgres.Open(dsn+"
// search_path=...")) -- the same pattern used by the other two copies.
//
// PERFORMANCE: FuzzCoreOperationSequence used to open+AutoMigrate a fresh
// in-memory SQLite DB on EVERY fuzz iteration (inside f.Fuzz). Building the
// world ONCE per testing.F (before f.Fuzz) instead, with an explicit
// per-iteration table reset, is what makes a real PostgreSQL round trip per
// input avoidable and is also a meaningful perf win on SQLite alone.
//
// RESET SCOPE: fuzzCoreResetTables is an EXPLICIT, hand-named table list,
// not derived from the migrated model set, so a model added to the
// migration list later doesn't silently escape the reset.

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
)

// fuzzCoreDBWorld is a *gorm.DB built ONCE per testing.F invocation and
// reused across every fuzz iteration -- see fuzzCoreResetTables for how
// callers restore a clean starting state between iterations.
type fuzzCoreDBWorld struct {
	backend string // "sqlite" or "postgres" -- failure messages only
	db      *gorm.DB
}

var fuzzCorePgSchemaSeq atomic.Int64

// buildFuzzCoreDBWorldSQLite opens a fresh in-memory SQLite DB and migrates
// models into it. Called once per testing.F, before f.Fuzz -- never inside
// the per-iteration callback. SetMaxOpenConns(1) matches the pre-existing
// behavior of the code this replaces (a plain ":memory:" DSN with no
// cache=shared gives each pool connection its own, separate database
// otherwise).
func buildFuzzCoreDBWorldSQLite(f *testing.F, models []any) *fuzzCoreDBWorld {
	f.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		f.Fatalf("open sqlite: %v", err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	for _, m := range models {
		if e := db.AutoMigrate(m); e != nil {
			f.Fatalf("migrate %T (sqlite): %v", m, e)
		}
	}
	return &fuzzCoreDBWorld{backend: "sqlite", db: db}
}

// buildFuzzCoreDBWorldPostgres returns nil (not a skip) when
// KEYORIX_TEST_PG_DSN is unset -- the caller decides whether that's fine,
// mirroring server/http/concurrent_linearizable_fuzz_test.go's
// buildLinearizabilityWorldPostgres.
func buildFuzzCoreDBWorldPostgres(f *testing.F, schemaPrefix string, models []any) *fuzzCoreDBWorld {
	f.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		return nil
	}
	n := fuzzCorePgSchemaSeq.Add(1)
	schema := fmt.Sprintf("%s_%d_%d", schemaPrefix, os.Getpid(), n)

	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		f.Fatalf("open postgres (admin): %v", err)
	}
	if err := admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error; err != nil {
		f.Fatalf("drop schema %s: %v", schema, err)
	}
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		f.Fatalf("create schema %s: %v", schema, err)
	}
	f.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if sqlDB, e := admin.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})

	db, err := gorm.Open(postgres.Open(dsn+" search_path="+schema), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		f.Fatalf("open postgres: %v", err)
	}
	for _, m := range models {
		if e := db.AutoMigrate(m); e != nil {
			f.Fatalf("migrate %T (postgres): %v", m, e)
		}
	}
	return &fuzzCoreDBWorld{backend: "postgres", db: db}
}

// buildFuzzCoreDBWorlds returns the SQLite world (always) plus the
// PostgreSQL world (when KEYORIX_TEST_PG_DSN is set) as a slice callers
// range over -- one iteration of the fuzz body per world.
func buildFuzzCoreDBWorlds(f *testing.F, schemaPrefix string, models []any) []*fuzzCoreDBWorld {
	worlds := []*fuzzCoreDBWorld{buildFuzzCoreDBWorldSQLite(f, models)}
	if pg := buildFuzzCoreDBWorldPostgres(f, schemaPrefix, models); pg != nil {
		worlds = append(worlds, pg)
	} else {
		f.Logf("KEYORIX_TEST_PG_DSN not set (%s) -- PostgreSQL backend skipped, SQLite only", schemaPrefix)
	}
	return worlds
}

// fuzzCoreResetTables restores w's DB to an empty-but-migrated state between
// fuzz iterations. tables must be given in dependent-first order (children
// before parents) -- Postgres TRUNCATE...CASCADE does not require this, but
// SQLite's plain per-table DELETE does not resolve FK ordering on its own.
func fuzzCoreResetTables(t *testing.T, w *fuzzCoreDBWorld, tables []string) {
	t.Helper()
	switch w.backend {
	case "postgres":
		stmt := "TRUNCATE TABLE " + strings.Join(tables, ", ") + " CASCADE"
		if err := w.db.Exec(stmt).Error; err != nil {
			t.Fatalf("[postgres] reset tables %v: %v", tables, err)
		}
	default: // "sqlite"
		for _, tbl := range tables {
			if err := w.db.Exec("DELETE FROM " + tbl).Error; err != nil {
				t.Fatalf("[sqlite] delete from %s: %v", tbl, err)
			}
		}
	}
}

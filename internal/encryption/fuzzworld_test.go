//go:build !windows

package encryption

// fuzzworld_test.go -- shared DB-world helper for the durability fuzzers that
// actually touch a database: FuzzDEKSweepCrashConsistency (a real DB
// transaction, ADR-010's re-encryption sweep) and the opCreate/opUpdate/
// opDelete paths of FuzzFaultInjectedOperations (SQL-callback fault
// injection via newSecretWorld). FuzzKEKRotationCrashConsistency and
// FuzzDEKRewrapCrashConsistency are deliberately NOT wired to this helper --
// grep confirms neither file references gorm.DB/sql.Open/sqlite/postgres
// anywhere: both harnesses model dek.key/kek.salt file durability only
// (write-pending -> rename -> fsync), with zero database interaction. Giving
// them a PostgreSQL path would add schema-create/migrate machinery that
// exercises no code those two harnesses don't already run identically on
// every backend, since there is no backend in their model at all.
//
// SQLite always runs (matching today's default -- no DSN, no behavior
// change). PostgreSQL additionally runs whenever KEYORIX_TEST_PG_DSN is set,
// via a schema-per-testing.F, gorm.Open(postgres.Open(dsn+" search_path=..."))
// -- the exact pattern server/http/concurrent_linearizable_fuzz_test.go's
// buildLinearizabilityWorldPostgres already uses in this repo (PR #1954's
// FuzzConcurrentOpsLinearizable), reused here rather than reinvented.
//
// PERFORMANCE: both consumers used to open+AutoMigrate a fresh in-memory
// SQLite DB on EVERY fuzz iteration (inside f.Fuzz). A schema-create +
// AutoMigrate round trip against a REAL PostgreSQL server on every fuzz
// input would be catastrophically slow (the investigation that produced this
// file measured today's SQLite-per-iteration throughput at roughly 1.5
// execs/s; a naive per-iteration Postgres schema would be far slower still).
// Instead, buildFuzzDBWorlds is called ONCE per testing.F (before f.Fuzz),
// exactly mirroring buildLinearizabilityWorldSQLite/buildLinearizabilityWorldPostgres,
// and fuzzResetTables clears the fuzzable rows between iterations without
// paying the schema cost again.
//
// RESET SCOPE: fuzzResetTables takes an EXPLICIT table-name list from the
// caller rather than deriving one from the migrated model set, so a model
// added to a caller's migration list later doesn't silently escape the reset
// (a drifted list fails safe -- an un-reset leftover table would surface as
// a spurious cross-iteration failure, not a silent pass). Both current
// callers include every table their harness's crash-and-recover cycle can
// write, INCLUDING the redo/marker tables (system_metadata for the sweep
// harness) -- a marker or row surviving from a PRIOR iteration's
// deliberately-interrupted crash would let the NEXT iteration's recovery
// oracle observe state left by the wrong crash and pass for the wrong
// reason. See docs/findings note in the PR description for the specific
// case (dek_rotation.promote_pending in system_metadata) this was checked
// against.

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

// fuzzDBWorld is a *gorm.DB built ONCE per testing.F invocation and reused
// across every fuzz iteration -- see fuzzResetTables for how callers restore
// a clean starting state between iterations.
type fuzzDBWorld struct {
	backend string // "sqlite" or "postgres" -- failure messages only
	db      *gorm.DB
}

var fuzzPgSchemaSeq atomic.Int64

// buildFuzzDBWorldSQLite opens a fresh in-memory SQLite DB and migrates
// models into it. Called once per testing.F, before f.Fuzz -- never inside
// the per-iteration callback.
func buildFuzzDBWorldSQLite(f *testing.F, models []any) *fuzzDBWorld {
	f.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		f.Fatalf("open sqlite: %v", err)
	}
	for _, m := range models {
		if e := db.AutoMigrate(m); e != nil {
			f.Fatalf("migrate %T (sqlite): %v", m, e)
		}
	}
	return &fuzzDBWorld{backend: "sqlite", db: db}
}

// buildFuzzDBWorldPostgres returns nil (not a skip) when KEYORIX_TEST_PG_DSN
// is unset -- the caller decides whether that's fine, mirroring
// server/http/concurrent_linearizable_fuzz_test.go's
// buildLinearizabilityWorldPostgres. schemaPrefix distinguishes this
// caller's schemas from any other Postgres-gated fixture sharing the same
// server (e.g. the two callers of this helper from each other, and from
// postgres_contention_helpers_test.go's "contend_*" schemas).
func buildFuzzDBWorldPostgres(f *testing.F, schemaPrefix string, models []any) *fuzzDBWorld {
	f.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		return nil
	}
	n := fuzzPgSchemaSeq.Add(1)
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
	return &fuzzDBWorld{backend: "postgres", db: db}
}

// buildFuzzDBWorlds returns the SQLite world (always) plus the PostgreSQL
// world (when KEYORIX_TEST_PG_DSN is set) as a slice callers range over --
// one iteration of the fuzz body per world, matching
// runLinearizabilityIteration's own shape.
func buildFuzzDBWorlds(f *testing.F, schemaPrefix string, models []any) []*fuzzDBWorld {
	worlds := []*fuzzDBWorld{buildFuzzDBWorldSQLite(f, models)}
	if pg := buildFuzzDBWorldPostgres(f, schemaPrefix, models); pg != nil {
		worlds = append(worlds, pg)
	} else {
		f.Logf("KEYORIX_TEST_PG_DSN not set (%s) -- PostgreSQL backend skipped, SQLite only", schemaPrefix)
	}
	return worlds
}

// fuzzResetTables restores w's DB to an empty-but-migrated state between
// fuzz iterations, cheaply enough to run on every input without reopening
// the world. tables must be given in dependent-first order (children before
// parents) -- Postgres TRUNCATE...CASCADE does not require this (CASCADE
// covers it), but SQLite's plain per-table DELETE does not resolve FK
// ordering on its own if FK enforcement is ever turned on for these DSNs, so
// callers order the list correctly rather than relying on backend-specific
// leniency.
//
// Returns a plain error rather than taking a testing.TB: one caller
// (runSweepCrashCase) has no *testing.T in scope -- it runs on a bare
// goroutine and reports failures by panicking, matching the rest of that
// file's convention -- while the other (newSecretWorld) does have one and
// uses t.Fatalf. Each caller adapts this return to its own idiom rather than
// this helper picking one for both.
func fuzzResetTables(w *fuzzDBWorld, tables []string) error {
	switch w.backend {
	case "postgres":
		stmt := "TRUNCATE TABLE " + strings.Join(tables, ", ") + " CASCADE"
		if err := w.db.Exec(stmt).Error; err != nil {
			return fmt.Errorf("[postgres] reset tables %v: %w", tables, err)
		}
	default: // "sqlite"
		for _, tbl := range tables {
			if err := w.db.Exec("DELETE FROM " + tbl).Error; err != nil {
				return fmt.Errorf("[sqlite] delete from %s: %w", tbl, err)
			}
		}
	}
	return nil
}

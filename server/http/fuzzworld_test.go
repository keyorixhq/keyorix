//go:build !windows

package http

// fuzzworld_test.go -- shared DB-world helper for FuzzKeyorixHTTPAPISequence
// and FuzzMultiTenantIsolation (both reuse buildAPIFuzzWorld,
// api_sequence_fuzz_test.go).
//
// DELIBERATE DUPLICATION, not an oversight: two other near-identical copies
// of this exact pattern exist in this repo --
// internal/encryption/fuzzworld_test.go (FuzzDEKSweepCrashConsistency,
// FuzzFaultInjectedOperations) and internal/core/fuzzworld_test.go
// (FuzzCoreOperationSequence). Go's unexported symbols don't cross package
// boundaries, and THIS package already has its own precedent for this exact
// shape: concurrent_linearizable_fuzz_test.go's own local
// buildLinearizabilityWorldSQLite/buildLinearizabilityWorldPostgres
// (FuzzConcurrentOpsLinearizable, PR #1954) duplicates it too, rather than
// sharing across fuzzers even within this one package. A tracking issue to
// extract a shared internal/testutil/fuzzworld package is filed once all
// three of these copies (this one, internal/encryption's, internal/core's)
// have landed.
//
// This copy is narrower than the other two: it only builds the bare
// *gorm.DB (SQLite always, PostgreSQL when KEYORIX_TEST_PG_DSN is set).
// buildAPIFuzzWorld (api_sequence_fuzz_test.go) takes that DB and builds
// the full rich world around it (router, core, principals, secrets) --
// unlike the encryption/core copies, that rich-world construction is
// itself the expensive, once-per-backend setup step here, not something
// reset per fuzz iteration. Both FuzzKeyorixHTTPAPISequence and
// FuzzMultiTenantIsolation already do their own fine-grained, existing
// per-iteration state cleanup inline (targeted DELETEs scoped to the exact
// rows a step can mutate) rather than a blanket table-reset list, so this
// copy does not need a fuzzResetTables equivalent -- there was nothing to
// change there, only the DB-open step needed a Postgres path.

import (
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	sqlite "github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

var apiFuzzPgSchemaSeq atomic.Int64

// apiFuzzDBWorldSQLite opens a fresh in-memory SQLite DB for buildAPIFuzzWorld.
// Called once per testing.F, before f.Fuzz.
func apiFuzzDBWorldSQLite(f *testing.F) *gorm.DB {
	f.Helper()
	db, err := gorm.Open(sqlite.Open(uniqueMemDSN("&_timeout=30000&_journal_mode=WAL")), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		f.Fatalf("open sqlite: %v", err)
	}
	if sqlDB, e := db.DB(); e == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	return db
}

// apiFuzzDBWorldPostgres returns nil (not a skip) when KEYORIX_TEST_PG_DSN
// is unset -- the caller decides whether that's fine, mirroring
// concurrent_linearizable_fuzz_test.go's buildLinearizabilityWorldPostgres.
func apiFuzzDBWorldPostgres(f *testing.F, schemaPrefix string) *gorm.DB {
	f.Helper()
	dsn := os.Getenv("KEYORIX_TEST_PG_DSN")
	if dsn == "" {
		return nil
	}
	n := apiFuzzPgSchemaSeq.Add(1)
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

	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		f.Fatalf("open postgres: %v", err)
	}
	return db
}

package pgdsn

import (
	"os"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestPGSearchPathDSN_KeywordValue(t *testing.T) {
	got := PGSearchPathDSN("host=localhost port=5432 dbname=x user=y sslmode=disable", "myschema")
	want := "host=localhost port=5432 dbname=x user=y sslmode=disable search_path=myschema"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPGSearchPathDSN_URLNoQuery(t *testing.T) {
	got := PGSearchPathDSN("postgres://user:pass@localhost:5432/db", "myschema")
	want := "postgres://user:pass@localhost:5432/db?search_path=myschema"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPGSearchPathDSN_URLWithQuery(t *testing.T) {
	got := PGSearchPathDSN("postgresql://user:pass@localhost:5432/db?sslmode=disable", "myschema")
	want := "postgresql://user:pass@localhost:5432/db?sslmode=disable&search_path=myschema"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPGReplaceDBName_KeywordValue(t *testing.T) {
	got := PGReplaceDBName("host=localhost port=5432 dbname=x user=y sslmode=disable", "newdb")
	want := "host=localhost port=5432 dbname=newdb user=y sslmode=disable"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPGReplaceDBName_KeywordValueNoDBName(t *testing.T) {
	got := PGReplaceDBName("host=localhost port=5432 user=y sslmode=disable", "newdb")
	want := "host=localhost port=5432 user=y sslmode=disable dbname=newdb"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPGReplaceDBName_URLNoQuery(t *testing.T) {
	got := PGReplaceDBName("postgres://user:pass@localhost:5432/db", "newdb")
	want := "postgres://user:pass@localhost:5432/newdb"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPGReplaceDBName_URLWithQuery(t *testing.T) {
	got := PGReplaceDBName("postgresql://user:pass@localhost:5432/db?sslmode=disable", "newdb")
	want := "postgresql://user:pass@localhost:5432/newdb?sslmode=disable"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestPGReplaceDBName_URLConnects is the red-proof: before this fix, the
// naive `strings.Fields`-based dbname= swap used verbatim in
// postgres_pk_rebuild_helpers_test.go silently appended a bogus trailing
// " dbname=..." token to a URL-style DSN instead of replacing the path — a
// no-op that left every "isolated" test pointed at the same shared base
// database. This proves PGReplaceDBName's output actually connects to a
// database named newName, for a URL DSN specifically.
func TestPGReplaceDBName_URLConnects(t *testing.T) {
	base := os.Getenv("KEYORIX_TEST_PG_DSN")
	if base == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — skipping live Postgres connectivity check")
	}

	admin, err := gorm.Open(postgres.Open(base), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open admin (base DSN as given): %v", err)
	}
	const dbName = "pgdsn_selftest_replacedbname"
	_ = admin.Exec("DROP DATABASE IF EXISTS " + dbName + " WITH (FORCE)").Error
	if err := admin.Exec("CREATE DATABASE " + dbName).Error; err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		cleaner, cerr := gorm.Open(postgres.Open(base), &gorm.Config{Logger: logger.Discard})
		if cerr == nil {
			_ = cleaner.Exec("DROP DATABASE IF EXISTS " + dbName + " WITH (FORCE)").Error
		}
	})

	scoped := PGReplaceDBName(base, dbName)
	db, err := gorm.Open(postgres.Open(scoped), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open scoped DSN %q: %v", scoped, err)
	}
	var currentDB string
	if err := db.Raw("SELECT current_database()").Scan(&currentDB).Error; err != nil {
		t.Fatalf("select current_database(): %v", err)
	}
	if currentDB != dbName {
		t.Fatalf("current_database() = %q, want %q — dbname was not replaced", currentDB, dbName)
	}
}

// TestPGSearchPathDSN_URLConnects is the red-proof: before this fix, the naive
// `base + " search_path=" + schema` concatenation — used verbatim in
// backend_differential_fuzz_test.go and 7 sibling files — fails to even open a
// connection against a URL-style DSN ("failed to configure TLS (sslmode is
// invalid)", confirmed live against this exact server during the 2026-09-22
// fuzz-speed audit). This proves PGSearchPathDSN's output actually connects
// and puts search_path where CREATE TABLE / SELECT will find it, for a URL
// DSN specifically — the form the naive version could never handle.
func TestPGSearchPathDSN_URLConnects(t *testing.T) {
	base := os.Getenv("KEYORIX_TEST_PG_DSN")
	if base == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set — skipping live Postgres connectivity check")
	}

	// Only meaningful for a URL-style DSN — a keyword/value DSN never hit this bug.
	admin, err := gorm.Open(postgres.Open(base), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open admin (base DSN as given): %v", err)
	}
	const schema = "pgdsn_selftest_urlconnect"
	if err := admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error; err != nil {
		t.Fatalf("drop schema: %v", err)
	}
	if err := admin.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
	})

	scoped := PGSearchPathDSN(base, schema)
	db, err := gorm.Open(postgres.Open(scoped), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open scoped DSN %q: %v", scoped, err)
	}
	var currentSchema string
	if err := db.Raw("SELECT current_schema()").Scan(&currentSchema).Error; err != nil {
		t.Fatalf("select current_schema(): %v", err)
	}
	if currentSchema != schema {
		t.Fatalf("current_schema() = %q, want %q — search_path was not applied", currentSchema, schema)
	}
}

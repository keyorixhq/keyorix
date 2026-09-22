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

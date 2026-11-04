package store_test

import (
	"strings"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// The differential fuzzer resets both backends before every iteration. A reset that
// fails on one backend leaves the previous iteration's rows there and shows up as a
// bogus "backend divergence" (the 2026-09-20 op=1 operand=48 report was the first
// operation after a wipe). diffWipeTables must therefore report the failure, naming
// the table, instead of discarding it.
func TestDiffWipeTablesReportsFailure(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:diffwipe_empty?mode=memory&cache=private"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	// No schema was migrated, so the first DELETE has no table to hit.
	err = diffWipeTables(db)
	if err == nil {
		t.Fatal("diffWipeTables returned nil on a database with no tables; a failed wipe would go unnoticed")
	}
	if !strings.Contains(err.Error(), "audit_events") {
		t.Fatalf("error does not name the failing table: %v", err)
	}
}

func TestDiffWipeTablesEmptiesTables(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:diffwipe_full?mode=memory&cache=private"), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	for _, tbl := range []string{
		"audit_events", "share_records", "secret_acls", "secret_versions", "secret_nodes",
		"sessions", "machine_identity_credentials", "machine_identities",
		"user_groups", "group_roles", "groups",
		"user_roles", "environments", "users", "projects",
	} {
		if err := db.Exec("CREATE TABLE " + tbl + " (id INTEGER)").Error; err != nil {
			t.Fatalf("create %s: %v", tbl, err)
		}
		if err := db.Exec("INSERT INTO " + tbl + " VALUES (1)").Error; err != nil {
			t.Fatalf("insert %s: %v", tbl, err)
		}
	}
	if err := diffWipeTables(db); err != nil {
		t.Fatalf("diffWipeTables: %v", err)
	}
	var n int64
	if err := db.Raw("SELECT count(*) FROM users").Scan(&n).Error; err != nil || n != 0 {
		t.Fatalf("users not emptied: n=%d err=%v", n, err)
	}
}

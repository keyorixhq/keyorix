package faultops

import (
	"os"
	"testing"

	"gorm.io/gorm"
)

// TestResetWorldTables_PostgresRowsAndBurntSequences gates resetWorldTables' Postgres path,
// which truncates only tables that hold a row and restarts every used sequence: a table
// with rows must come back empty, and a table that is empty again but whose serial was
// burnt by a rolled-back insert (what a faulted write leaves behind) must restart at 1,
// or the reference and faulted worlds would hash different ids. TestWorldReuseSoundness
// covers the same through whole iterations; this one names the two shapes.
func TestResetWorldTables_PostgresRowsAndBurntSequences(t *testing.T) {
	if os.Getenv(pgDSNEnv) == "" {
		t.Skip("Postgres-only: the SQLite reset deletes every table")
	}
	w := buildReusableFaultWorld(t, nil)
	for _, ddl := range []string{
		"CREATE TABLE zz_reset_rows (id serial PRIMARY KEY, v text)",
		"CREATE TABLE zz_reset_burnt (id serial PRIMARY KEY, v text)",
		"CREATE TABLE zz_reset_untouched (id serial PRIMARY KEY, v text)",
	} {
		if err := w.db.Exec(ddl).Error; err != nil {
			t.Fatalf("%s: %v", ddl, err)
		}
	}
	for range 3 {
		if err := w.db.Exec("INSERT INTO zz_reset_rows (v) VALUES ('x')").Error; err != nil {
			t.Fatal(err)
		}
	}
	rollback := w.db.Begin()
	if err := rollback.Exec("INSERT INTO zz_reset_burnt (v) VALUES ('x')").Error; err != nil {
		t.Fatal(err)
	}
	if err := rollback.Rollback().Error; err != nil {
		t.Fatal(err)
	}

	if err := resetWorldTables(w.db, w.backend); err != nil {
		t.Fatal(err)
	}
	for _, tbl := range []string{"zz_reset_rows", "zz_reset_burnt", "zz_reset_untouched"} {
		var n int64
		if err := w.db.Table(tbl).Count(&n).Error; err != nil || n != 0 {
			t.Fatalf("%s: %d rows after reset (err %v), want 0", tbl, n, err)
		}
		var id int
		if err := insertReturningID(w.db, tbl, &id); err != nil || id != 1 {
			t.Fatalf("%s: first id after reset is %d (err %v), want 1", tbl, id, err)
		}
	}
}

func insertReturningID(db *gorm.DB, tbl string, id *int) error {
	return db.Raw("INSERT INTO " + tbl + " (v) VALUES ('y') RETURNING id").Scan(id).Error // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query -- tbl is a literal from this test
}

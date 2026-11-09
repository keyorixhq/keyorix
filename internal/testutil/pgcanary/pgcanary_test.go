package pgcanary

import (
	"errors"
	"flag"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

var sweep = flag.Bool("pgcanary-sweep", false, "drop every w7_* database left by a killed run")

// TestSweepStaleDatabases runs only on request: go test -run SweepStale -pgcanary-sweep.
func TestSweepStaleDatabases(t *testing.T) {
	if !*sweep {
		t.Skip("set -pgcanary-sweep to drop leftovers")
	}
	dropped := SweepStale(t)
	t.Logf("dropped %d databases", len(dropped))
}

// TestWorldLifecycle proves what the harnesses depend on against the real server:
// the database name carries the prefix, the tracer sees server errors with their
// DETAIL, Reset restores rows and sequences, and Dump sees text and bytea cells.
func TestWorldLifecycle(t *testing.T) {
	w := Open(t, "lifecycle", "")
	if !strings.Contains(w.DSN, Prefix) {
		t.Fatalf("database name does not carry the prefix %s", Prefix)
	}
	v, err := w.PostgresVersion()
	if err != nil {
		t.Fatal(err)
	}
	settings, err := w.ServerLogSettings()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("server: %s", v)
	t.Logf("server log settings: %v", settings)

	mustExec := func(stmt string) {
		t.Helper()
		if err := w.DB.Exec(stmt).Error; err != nil {
			t.Fatalf("%q: %v", stmt, err)
		}
	}
	rtt := time.Now()
	for range 20 {
		mustExec(`SELECT 1`)
	}
	t.Logf("20 x SELECT 1 took %v", time.Since(rtt))
	mustExec(`CREATE TABLE w7_probe (id BIGSERIAL PRIMARY KEY, name TEXT UNIQUE NOT NULL, secret BYTEA)`)
	mustExec(`INSERT INTO w7_probe (name, secret) VALUES ('seeded', 'x')`)
	w.Snapshot(t)

	// The driver's error text omits DETAIL; the tracer must not.
	err = w.DB.Exec(`INSERT INTO w7_probe (name) VALUES ('seeded')`).Error
	pg, ok := errors.AsType[*pgconn.PgError](err)
	if !ok || pg.Code != "23505" {
		t.Fatalf("want a 23505 from the duplicate, got %v", err)
	}
	if strings.Contains(err.Error(), "seeded") {
		t.Fatalf("pgconn.PgError.Error() quoted the value, so its contract changed: %v", err)
	}
	entries := w.Tracer.Drain()
	if len(entries) == 0 || !strings.Contains(entries[len(entries)-1].Detail, "seeded") {
		t.Fatalf("tracer did not record DETAIL: %+v", entries)
	}

	mustExec(`INSERT INTO w7_probe (name) VALUES ('extra')`)
	resetAt := time.Now()
	if err := w.Reset(); err != nil {
		t.Fatal(err)
	}
	t.Logf("one Reset took %v", time.Since(resetAt))
	var names []string
	if err := w.DB.Raw(`SELECT name FROM w7_probe ORDER BY id`).Scan(&names).Error; err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0] != "seeded" {
		t.Fatalf("reset left %v", names)
	}
	var next int64
	mustExec(`INSERT INTO w7_probe (name) VALUES ('after-reset')`)
	if err := w.DB.Raw(`SELECT id FROM w7_probe WHERE name = 'after-reset'`).Scan(&next).Error; err != nil {
		t.Fatal(err)
	}
	if next != 2 {
		t.Fatalf("sequence after reset: next id %d, want 2", next)
	}

	mustExec(`UPDATE w7_probe SET secret = convert_to('bytea-cell', 'UTF8') WHERE name = 'after-reset'`)
	dumpAt := time.Now()
	dump, err := w.Dump()
	t.Logf("one Dump took %v", time.Since(dumpAt))
	if err != nil {
		t.Fatal(err)
	}
	var cell string
	for _, o := range dump {
		if o.Channel == "db:w7_probe" {
			cell = string(o.Data)
		}
	}
	// hex of "bytea-cell": a bytea cell must be searchable as hex.
	if !strings.Contains(cell, "after-reset") || !strings.Contains(cell, "62797465612d63656c6c") {
		t.Fatalf("dump missed a cell: %q", cell)
	}
}

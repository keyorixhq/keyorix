package storage

import (
	"database/sql"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestW6ConnProbe(t *testing.T) {
	db, err := sql.Open("pgx", pgTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var ver string
	if err := db.QueryRow("SELECT version()").Scan(&ver); err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Log(ver)
}

// TestW6Sweep drops only databases whose names start with w6_, this session's prefix.
func TestW6Sweep(t *testing.T) {
	db, err := sql.Open("pgx", pgTestDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.Query(`SELECT datname FROM pg_database WHERE datname LIKE 'w6\_%'`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	_ = rows.Close()
	for _, n := range names {
		if !strings.HasPrefix(n, "w6_") {
			t.Fatalf("refusing %q", n)
		}
		if _, err := db.Exec(`DROP DATABASE IF EXISTS "` + n + `" WITH (FORCE)`); err != nil {
			t.Errorf("drop %s: %v", n, err)
		}
	}
	t.Logf("dropped %d: %v", len(names), names)
}

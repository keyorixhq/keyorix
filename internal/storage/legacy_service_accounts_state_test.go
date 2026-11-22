package storage

// legacy_service_accounts_state_test.go — #2541 stage 1: the boot migration
// records whether api_clients/api_tokens are empty (system_metadata key
// service_accounts_purge_v1), on every upgrade path the repository has a real
// release snapshot for, and never touches a row of either table.
//
// The key is written as a literal here, not via the production constant, so
// these tests compile against a tree without the step and fail on the missing
// marker (a real red, not a compile error).

import (
	"bytes"
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gorm.io/gorm"
)

const legacySAMarkerKeyLiteral = "service_accounts_purge_v1"

// legacySAState reads both table counts and the marker through a raw handle.
type legacySAState struct {
	clients, tokens int64
	marker          string
	markerFound     bool
}

func readLegacySAState(t *testing.T, raw *sql.DB, placeholder string) legacySAState {
	t.Helper()
	var s legacySAState
	if err := raw.QueryRow("SELECT COUNT(*) FROM api_clients").Scan(&s.clients); err != nil {
		t.Fatalf("count api_clients: %v", err)
	}
	if err := raw.QueryRow("SELECT COUNT(*) FROM api_tokens").Scan(&s.tokens); err != nil {
		t.Fatalf("count api_tokens: %v", err)
	}
	err := raw.QueryRow("SELECT value FROM system_metadata WHERE key = "+placeholder, legacySAMarkerKeyLiteral).Scan(&s.marker)
	switch {
	case err == sql.ErrNoRows:
	case err != nil:
		t.Fatalf("read marker: %v", err)
	default:
		s.markerFound = true
	}
	return s
}

func migrateSQLiteFile(t *testing.T, dbPath string) (*gorm.DB, *sql.DB) {
	t.Helper()
	gdb, err := openSQLiteGorm(sqliteDSN(dbPath))
	if err != nil {
		t.Fatalf("open %s: %v", dbPath, err)
	}
	raw, err := gdb.DB()
	if err != nil {
		t.Fatalf("raw handle: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := MigrateExisting(gdb); err != nil {
		t.Fatalf("migrate %s: %v", dbPath, err)
	}
	return gdb, raw
}

// TestLegacyServiceAccountsState_SQLiteUpgradePaths is the emptiness
// verification #2541 asks for, on SQLite: a fresh install and every release
// snapshot in testdata/upgrade-snapshots (v0.91.0 ... v0.96.3, written by each
// release's own core) migrate to empty api_clients/api_tokens and the "empty"
// marker. Run with -v: each path logs one VERIFY line for the PR.
func TestLegacyServiceAccountsState_SQLiteUpgradePaths(t *testing.T) {
	sources := append([]string{"fresh"}, ugSources...)
	for _, src := range sources {
		t.Run(src, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "keyorix.db")
			if src != "fresh" {
				tpl, err := ugLoadTemplate(src)
				if err != nil {
					t.Fatalf("load %s snapshot: %v", src, err)
				}
				if err := os.WriteFile(dbPath, tpl.image, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, raw := migrateSQLiteFile(t, dbPath)
			got := readLegacySAState(t, raw, "?")
			t.Logf("VERIFY sqlite %-8s api_clients=%d api_tokens=%d marker=%q found=%v",
				src, got.clients, got.tokens, got.marker, got.markerFound)
			if got.clients != 0 || got.tokens != 0 {
				t.Fatalf("%s: legacy tables not empty after upgrade: %+v", src, got)
			}
			if !got.markerFound || got.marker != "empty" {
				t.Fatalf("%s: %s marker = %q (found %v), want \"empty\"", src, legacySAMarkerKeyLiteral, got.marker, got.markerFound)
			}
		})
	}
}

// TestLegacyServiceAccountsState_RowsClearMarkerAndAreKept: a row in either
// table removes the marker, logs a warning with the counts, and the row stays
// (the step observes, it never purges); once the rows are gone the next boot
// records the marker again.
func TestLegacyServiceAccountsState_RowsClearMarkerAndAreKept(t *testing.T) {
	for _, table := range []string{"api_clients", "api_tokens"} {
		t.Run(table, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "keyorix.db")
			_, raw := migrateSQLiteFile(t, dbPath)
			if s := readLegacySAState(t, raw, "?"); !s.markerFound {
				t.Fatalf("fresh install: marker missing: %+v", s)
			}
			insert := map[string]string{
				"api_clients": "INSERT INTO api_clients (name, client_id, client_secret) VALUES ('legacy', 'legacy-client', 'hash')",
				"api_tokens":  "INSERT INTO api_tokens (client_id, token, scope) VALUES (1, 'legacy-token-hash', 'read')",
			}[table]
			if _, err := raw.Exec(insert); err != nil {
				t.Fatalf("insert legacy row: %v", err)
			}
			_ = raw.Close()

			var logs bytes.Buffer
			prev := log.Writer()
			log.SetOutput(&logs)
			_, raw = migrateSQLiteFile(t, dbPath)
			log.SetOutput(prev)

			s := readLegacySAState(t, raw, "?")
			if s.markerFound {
				t.Fatalf("marker still present with a row in %s: %+v", table, s)
			}
			if s.clients+s.tokens != 1 {
				t.Fatalf("the step changed rows: %+v, want exactly the one inserted", s)
			}
			if !strings.Contains(logs.String(), "WARNING: legacy service-account tables are not empty") {
				t.Fatalf("no warning logged; log was:\n%s", logs.String())
			}

			if _, err := raw.Exec("DELETE FROM " + table); err != nil {
				t.Fatal(err)
			}
			_ = raw.Close()
			_, raw = migrateSQLiteFile(t, dbPath)
			if s := readLegacySAState(t, raw, "?"); !s.markerFound || s.marker != "empty" {
				t.Fatalf("marker not recorded again after the rows were deleted: %+v", s)
			}
		})
	}
}

// TestLegacyServiceAccountsState_PostgresUpgradePaths is the Postgres leg of the
// verification: a fresh database and every testdata/upgrade-snapshots-pg release
// snapshot. Skips without KEYORIX_TEST_PG_DSN.
func TestLegacyServiceAccountsState_PostgresUpgradePaths(t *testing.T) {
	base := pgTestDSN(t)
	sources := append([]string{"fresh"}, ugSources...)
	for _, src := range sources {
		t.Run(src, func(t *testing.T) {
			_, dsn := pgCreateDatabase(t, base)
			if src != "fresh" {
				tpl, err := pgLoadTemplate(src)
				if err != nil {
					t.Fatalf("load %s pg snapshot: %v", src, err)
				}
				replay := pgOpenRaw(t, dsn)
				if _, err := replay.Exec(strings.ReplaceAll(tpl.script, pgStmtSep, ";\n")); err != nil {
					t.Fatalf("replay %s: %v", src, redactDSN(err))
				}
				_ = replay.Close()
			}
			gdb := pgOpenGorm(t, dsn)
			if err := MigrateExisting(gdb); err != nil {
				t.Fatalf("migrate %s: %v", src, redactDSN(err))
			}
			raw := pgOpenRaw(t, dsn)
			defer func() { _ = raw.Close() }()
			got := readLegacySAState(t, raw, "$1")
			t.Logf("VERIFY postgres %-8s api_clients=%d api_tokens=%d marker=%q found=%v",
				src, got.clients, got.tokens, got.marker, got.markerFound)
			if got.clients != 0 || got.tokens != 0 {
				t.Fatalf("%s: legacy tables not empty after upgrade: %+v", src, got)
			}
			if !got.markerFound || got.marker != "empty" {
				t.Fatalf("%s: marker = %q (found %v), want \"empty\"", src, got.marker, got.markerFound)
			}
		})
	}
}

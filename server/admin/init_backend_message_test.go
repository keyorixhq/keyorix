package admin

// init_backend_message_test.go: #3523. `admin init` must say which backend it
// initialised, for both backends, and a PostgreSQL config must not leave any
// SQLite file behind.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

func TestInitializeAdminDatabase_NamesTheBackend(t *testing.T) {
	t.Run("postgres", func(t *testing.T) {
		dir := t.TempDir()
		dbPath := filepath.Join(dir, "data", "keyorix.db")
		cfg := &config.Config{}
		cfg.Storage.Type = "postgres"
		cfg.Storage.Database.Path = dbPath
		cfg.Storage.Database.DSN = "host=localhost dbname=x sslmode=disable"

		out, err := captureStdout(t, func() error { return initializeAdminDatabase(cfg) })
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, "postgres") || strings.Contains(out, "SQLite") {
			t.Fatalf("output must name PostgreSQL and not SQLite, got:\n%s", out)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("postgres init left files in the data dir: %v", entries)
		}
	})

	t.Run("sqlite", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "keyorix.db")
		cfg := &config.Config{}
		cfg.Storage.Type = "sqlite"
		cfg.Storage.Database.Path = dbPath

		out, err := captureStdout(t, func() error { return initializeAdminDatabase(cfg) })
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, "SQLite") || !strings.Contains(out, dbPath) {
			t.Fatalf("output must name SQLite and the file %s, got:\n%s", dbPath, out)
		}
		if _, err := os.Stat(dbPath); err != nil {
			t.Fatalf("sqlite file not created: %v", err)
		}
	})
}

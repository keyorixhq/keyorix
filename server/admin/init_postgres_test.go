package admin

// init_postgres_test.go: #2980. The shipped config template's PostgreSQL
// instructions must produce a config that loads, and `admin init` must not
// create a SQLite file for a deployment configured for another backend.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/configs"
	"github.com/keyorixhq/keyorix/internal/config"
)

// Following the template's own PostgreSQL instructions (set storage.type, then
// uncomment Option A) must load under the strict config loader. The old hint told
// operators to uncomment "type: postgres" under storage.database, which the strict
// loader rejects ("field type not found in type config.DatabaseConfig").
func TestConfigTemplate_PostgresRecipeLoads(t *testing.T) {
	tpl := string(configs.DefaultConfigTemplate)

	typeLine := regexp.MustCompile(`(?m)^  type: sqlite\b.*$`)
	if !typeLine.MatchString(tpl) {
		t.Fatal("template no longer has the top-level storage `type: sqlite` line this test edits")
	}
	tpl = typeLine.ReplaceAllString(tpl, "  type: postgres")
	pathLine := regexp.MustCompile(`(?m)^    path: "keyorix.db"\n`)
	tpl = pathLine.ReplaceAllString(tpl, "")
	const dsnHint = `    # dsn: "host=localhost user=keyorix dbname=keyorix port=5432 sslmode=require"`
	if !strings.Contains(tpl, dsnHint) {
		t.Fatal("template no longer carries the commented Option A dsn line")
	}
	tpl = strings.Replace(tpl, dsnHint, strings.Replace(dsnHint, "# ", "", 1), 1)

	path := filepath.Join(t.TempDir(), "keyorix.yaml")
	if err := os.WriteFile(path, []byte(tpl), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("template's PostgreSQL recipe does not load: %v", err)
	}
	if cfg.Storage.Type != "postgres" || cfg.Storage.Database.DSN == "" {
		t.Fatalf("recipe loaded but not as postgres+dsn: type=%q dsn-set=%v", cfg.Storage.Type, cfg.Storage.Database.DSN != "")
	}
}

// No commented-out key under storage.database may be one DatabaseConfig does not have.
func TestConfigTemplate_NoCommentedTypeUnderDatabase(t *testing.T) {
	for i, line := range strings.Split(string(configs.DefaultConfigTemplate), "\n") {
		if strings.HasPrefix(line, "    # type:") {
			t.Errorf("template line %d hints a `type:` key under storage.database, which is not a field there (the selector is storage.type): %q", i+1, line)
		}
	}
}

// A non-SQLite deployment gets no SQLite file from `admin init`.
func TestInitializeAdminDatabase_NonSQLiteBackendCreatesNoFile(t *testing.T) {
	for _, typ := range []string{"postgres", "postgresql"} {
		t.Run(typ, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "data", "keyorix.db")
			cfg := &config.Config{}
			cfg.Storage.Type = typ
			cfg.Storage.Database.Path = dbPath
			cfg.Storage.Database.DSN = "host=localhost dbname=x"

			if err := initializeAdminDatabase(cfg); err != nil {
				t.Fatalf("initializeAdminDatabase: %v", err)
			}
			if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
				t.Fatalf("storage.type=%s but a SQLite file was created at %s (stat err: %v)", typ, dbPath, err)
			}
			if _, err := os.Stat(filepath.Dir(dbPath)); !os.IsNotExist(err) {
				t.Fatalf("storage.type=%s but the SQLite data dir was created (stat err: %v)", typ, err)
			}
		})
	}
}

// The SQLite path is unchanged.
func TestInitializeAdminDatabase_SQLiteStillCreatesFile(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "keyorix.db")
	cfg := &config.Config{}
	cfg.Storage.Type = "sqlite"
	cfg.Storage.Database.Path = dbPath
	if err := initializeAdminDatabase(cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("sqlite database file not created: %v", err)
	}
}

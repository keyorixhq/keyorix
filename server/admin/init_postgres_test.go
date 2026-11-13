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

// runInitInEmptyDir runs `admin init` end to end in a fresh working directory
// (the default ./keyorix.yaml) and returns that directory plus init's error.
// The package-level flag variables are restored afterwards.
func runInitInEmptyDir(t *testing.T, storageType, preWrittenConfig string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	origCfg, origType, origDev := configPathFlag, initStorageType, initDev
	t.Cleanup(func() { configPathFlag, initStorageType, initDev = origCfg, origType, origDev })
	configPathFlag = "keyorix.yaml" // config writes must be relative to the cwd
	initStorageType = storageType
	initDev = false
	if preWrittenConfig != "" {
		if err := os.WriteFile(filepath.Join(dir, configPathFlag), []byte(preWrittenConfig), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, runAdminInit(initCmd, nil)
}

// sqliteArtifacts lists every SQLite database/sidecar file under dir:
// keyorix.db, -shm, -wal, .server.lock and the like.
func sqliteArtifacts(t *testing.T, dir string) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		n := d.Name()
		if strings.Contains(n, ".db") || strings.HasSuffix(n, ".server.lock") || strings.Contains(n, ".sqlite") {
			found = append(found, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// #3523: init with --storage-type postgres in an empty directory writes the
// config and creates no SQLite file at all.
func TestAdminInit_StorageTypePostgres_EmptyDirCreatesNoSQLiteFiles(t *testing.T) {
	dir, err := runInitInEmptyDir(t, "postgres", "")
	if err != nil {
		t.Fatalf("init --storage-type postgres: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "keyorix.yaml")); err != nil {
		t.Fatalf("config not written: %v", err)
	}
	if got := sqliteArtifacts(t, dir); len(got) != 0 {
		t.Fatalf("--storage-type postgres left SQLite files behind: %v", got)
	}
}

// #3523: a supplied config whose storage.type is postgres (no flag) leaves the
// database alone even when init then cannot reach it: no SQLite file appears.
func TestAdminInit_PostgresConfigSupplied_CreatesNoSQLiteFiles(t *testing.T) {
	const pgConfig = `storage:
  type: postgres
  database:
    dsn: "host=127.0.0.1 port=1 user=x dbname=x sslmode=disable connect_timeout=1"
`
	dir, err := runInitInEmptyDir(t, "", pgConfig)
	if err == nil {
		t.Log("init succeeded against the placeholder DSN (unexpected but harmless)")
	}
	if got := sqliteArtifacts(t, dir); len(got) != 0 {
		t.Fatalf("storage.type: postgres config but init created SQLite files: %v (init err: %v)", got, err)
	}
}

// The SQLite default is unchanged: no flag, no config creates keyorix.db.
func TestAdminInit_DefaultStillCreatesSQLiteDatabase(t *testing.T) {
	dir, err := runInitInEmptyDir(t, "", "")
	if err != nil {
		t.Fatalf("default init: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "keyorix.db")); err != nil {
		t.Fatalf("default init no longer creates keyorix.db: %v", err)
	}
}

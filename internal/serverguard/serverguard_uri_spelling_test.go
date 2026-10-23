package serverguard

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage"
)

// REVIEW-SERVERGUARD-RECOVERYKEY-1: SQLite also opens a database given as a
// "file:" URI, so a server configured with "file:/data/secrets.db" and an
// admin command with "/data/secrets.db" use one database. The sidecar lock was
// named after the raw string, so the two locked different files
// ("file:/data/secrets.db.server.lock" relative to the working directory) and
// both ran at once. Likewise a real database under a directory whose name
// contains "mode=memory" was taken for an in-memory one and got no lock.

// sqliteSameDatabase is the precondition: spelling opens the database file at
// canonical (a table created through it is visible there), so a sidecar
// mismatch between the two would be a real gap, not a theoretical one.
func sqliteSameDatabase(t *testing.T, spelling, canonical, table string) {
	t.Helper()
	cfg := &config.Config{Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: spelling}}}
	db, err := storage.OpenGormDB(cfg)
	if err != nil {
		t.Fatalf("precondition: open %q: %v", spelling, err)
	}
	if err := db.Exec("CREATE TABLE " + table + " (x int)").Error; err != nil {
		t.Fatalf("precondition: create table through %q: %v", spelling, err)
	}
	closeDB(db)
	cdb, err := storage.OpenGormDB(&config.Config{Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: canonical}}})
	if err != nil {
		t.Fatalf("precondition: open %q: %v", canonical, err)
	}
	defer closeDB(cdb)
	if !cdb.Migrator().HasTable(table) {
		t.Fatalf("precondition: %q does not open the database at %q", spelling, canonical)
	}
}

func TestSQLiteURISpellings_MeetOnTheSameLock(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "my data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(data)
	canonical := filepath.Join(data, "secrets.db")
	spellings := []string{
		"file:" + canonical,
		"file://" + canonical,
		"file://localhost" + canonical,
		"file:" + canonical + "?cache=shared",
		"file:secrets.db",
		"file:" + strings.ReplaceAll(canonical, " ", "%20"),
	}
	for i, s := range spellings {
		sqliteSameDatabase(t, s, canonical, fmt.Sprintf("probe_%d", i))
	}
	cfgFor := func(p string) *config.Config {
		return &config.Config{Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: p}}}
	}
	for _, s := range spellings {
		for _, pair := range [][2]string{{s, canonical}, {canonical, s}} {
			p, err := AcquirePresence(cfgFor(pair[0]))
			if err != nil {
				t.Fatalf("AcquirePresence(%q): %v", pair[0], err)
			}
			if x, err := AcquireExclusive(cfgFor(pair[1])); err == nil {
				_ = x.Release()
				t.Errorf("a server on %q and an admin command on %q both held the lock", pair[0], pair[1])
			}
			_ = p.Release()
		}
	}
}

func TestSQLiteModeMemoryDirectoryName_StillLocked(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mode=memory")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "secrets.db")
	sqliteSameDatabase(t, dbPath, dbPath, "probe")
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("precondition: no database file on disk at %q: %v", dbPath, err)
	}
	cfg := &config.Config{Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: dbPath}}}
	p, err := AcquirePresence(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Release() //nolint:errcheck
	if x, err := AcquireExclusive(cfg); err == nil {
		_ = x.Release()
		t.Fatal("a server and an admin command both held the lock on a real database under a \"mode=memory\" directory")
	}
	// The real in-memory forms still need no lock.
	for _, mem := range []string{":memory:", "file::memory:?cache=shared", "file:x?mode=memory", "x.db?mode=memory&cache=shared"} {
		if _, real := sqliteLockPath(&config.Config{Storage: config.StorageConfig{Database: config.DatabaseConfig{Path: mem}}}); real {
			t.Errorf("%q is in-memory but got a sidecar lock path", mem)
		}
	}
}

func closeDB(db interface{ DB() (*sql.DB, error) }) {
	if s, err := db.DB(); err == nil {
		_ = s.Close()
	}
}

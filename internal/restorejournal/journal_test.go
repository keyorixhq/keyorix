package restorejournal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

func TestWriteReadRemove_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	want := Journal{Backend: "postgres", Token: "abc", Timestamp: "20261022T000000Z", Overwrite: true,
		Entries: []Entry{{Path: "dek.key", Staged: "dek.key.restoring-1"}, {Path: "secrets.db", Staged: "s", SQLiteDB: true}}}
	if err := Write(path, want); err != nil {
		t.Fatal(err)
	}
	got, found, err := Read(path)
	if err != nil || !found {
		t.Fatalf("Read: found=%v err=%v", found, err)
	}
	if got.Token != want.Token || len(got.Entries) != 2 || !got.Entries[1].SQLiteDB || got.Version != Version {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if err := Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, found, err := Read(path); found || err != nil {
		t.Fatalf("after Remove: found=%v err=%v", found, err)
	}
}

// A journal that exists but cannot be read as one is an error, never
// "absent": treating it as absent would let a restore or a boot proceed over
// a half-installed key set.
func TestRead_MalformedOrForeignVersion_IsAnError(t *testing.T) {
	for name, content := range map[string]string{"garbage": "not json", "version": `{"version": 99}`} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), FileName)
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if _, found, err := Read(path); err == nil || !found {
				t.Fatalf("want an error with found=true, got found=%v err=%v", found, err)
			}
		})
	}
}

func TestDir_PerBackend(t *testing.T) {
	sqlite := &config.Config{}
	sqlite.Storage.Type = "sqlite"
	sqlite.Storage.Database.Path = "/data/secrets.db"
	if d, err := Dir(sqlite); err != nil || d != "/data" {
		t.Fatalf("sqlite: %q %v", d, err)
	}
	pg := &config.Config{}
	pg.Storage.Type = "postgresql"
	pg.Storage.Encryption.Enabled = true
	pg.Storage.Encryption.SaltPath = "/keys/kek.salt"
	pg.Storage.Encryption.DEKPath = "/keys/dek.key"
	if d, err := Dir(pg); err != nil || d != "/keys" {
		t.Fatalf("postgres: %q %v", d, err)
	}
	remote := &config.Config{}
	remote.Storage.Type = "remote"
	if d, err := Dir(remote); err != nil || d != "" {
		t.Fatalf("remote: %q %v", d, err)
	}
}

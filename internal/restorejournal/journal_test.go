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

// TestDir_RelativePathIsMadeAbsolute: a relative database path resolves
// against the working directory, as it does for the server, and the journal
// location is reported absolute so messages name the real file.
func TestDir_RelativePathIsMadeAbsolute(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Storage.Type = "sqlite"
	cfg.Storage.Database.Path = "data/secrets.db"
	if d, err := Dir(cfg); err != nil || d != filepath.Join(wd, "data") {
		t.Fatalf("got %q %v, want %q", d, err, filepath.Join(wd, "data"))
	}
}

// TestWrite_SyncsEveryStagedDirectoryBeforeTheJournal: a key file staged in
// a directory other than the journal's must have its directory entry on disk
// before a journal naming it is, or power loss can keep the journal and lose
// the staged file. Write fsyncs each distinct staged-file directory, then the
// journal's own directory after the rename.
func TestWrite_SyncsEveryStagedDirectoryBeforeTheJournal(t *testing.T) {
	jdir, keyDir, saltDir := t.TempDir(), t.TempDir(), t.TempDir()
	jpath := filepath.Join(jdir, FileName)
	var synced []string
	journalOnDisk := map[string]bool{}
	orig := syncDir
	t.Cleanup(func() { syncDir = orig })
	syncDir = func(dir string) error {
		synced = append(synced, dir)
		_, err := os.Stat(jpath)
		journalOnDisk[dir] = err == nil
		return orig(dir)
	}
	j := Journal{Backend: "postgres", Timestamp: "20261023T000000Z", Entries: []Entry{
		{Path: filepath.Join(keyDir, "dek.key"), Staged: filepath.Join(keyDir, "dek.key.restoring-1")},
		{Path: filepath.Join(keyDir, "other.key"), Staged: filepath.Join(keyDir, "other.key.restoring-2")},
		{Path: filepath.Join(saltDir, "kek.salt"), Staged: filepath.Join(saltDir, "kek.salt.restoring-3")},
	}}
	if err := Write(jpath, j); err != nil {
		t.Fatal(err)
	}
	want := []string{keyDir, saltDir, jdir}
	if len(synced) != len(want) {
		t.Fatalf("synced %v, want %v", synced, want)
	}
	for i, d := range want {
		if synced[i] != d {
			t.Fatalf("synced %v, want %v", synced, want)
		}
	}
	if journalOnDisk[keyDir] || journalOnDisk[saltDir] {
		t.Fatalf("a staged-file directory was synced after the journal appeared: %v", journalOnDisk)
	}
}

func TestHashBytesMatchesHashFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("key material"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := HashFile(p)
	if err != nil || got != HashBytes([]byte("key material")) || len(got) != 64 {
		t.Fatalf("HashFile=%q err=%v", got, err)
	}
}

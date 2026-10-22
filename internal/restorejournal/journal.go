// Package restorejournal is the on-disk journal `keyorix-server admin restore`
// keeps while it installs a restore whose halves live in different places:
// the key-material files on the filesystem, and the rows in the database
// (PostgreSQL) or a database file (SQLite). Neither filesystem nor database
// offers a transaction spanning both, so restore stages every new file next
// to its target first, records them here, and only then commits; a process
// killed in between leaves this journal behind. While it exists the server
// refuses to start (RefuseIfPresent, called from the boot-time key-set
// check), and `admin restore --recover` finishes or undoes the restore.
package restorejournal

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
)

// FileName is the journal's name inside Dir(cfg).
const FileName = ".keyorix-restore-journal.json"

// Version is the journal format this binary writes and reads.
const Version = 1

// Entry is one file the restore installs: Staged is a complete, fsynced
// replacement in the same directory as Path, renamed over it on commit.
type Entry struct {
	Path   string `json:"path"`
	Staged string `json:"staged"`
	// SQLiteDB marks the database file: its -wal/-shm sidecars belong to the
	// file being replaced and are moved aside with it.
	SQLiteDB bool `json:"sqlite_db,omitempty"`
}

// Journal records one restore between staging and completion.
type Journal struct {
	Version int    `json:"version"`
	Backend string `json:"backend"` // "sqlite" or "postgres"
	// Token is written into system_metadata by the PostgreSQL load
	// transaction: present in the database means the data committed (roll
	// forward), absent means it did not (roll back). Empty for SQLite, whose
	// journal is written only once every staged file is complete, so it is
	// always rolled forward.
	Token string `json:"token,omitempty"`
	// Timestamp names the moved-aside originals (<path>.pre-restore-<ts>).
	Timestamp string  `json:"timestamp"`
	Overwrite bool    `json:"overwrite"`
	Entries   []Entry `json:"entries"`

	// The steps that follow a commit, so a recovery can finish them.
	CompletedEvent        string `json:"completed_event"`
	RollbackOverrideEvent string `json:"rollback_override_event,omitempty"`
	WitnessPath           string `json:"witness_path,omitempty"`
	WitnessValue          string `json:"witness_value,omitempty"`
}

// IsPostgres reports whether cfg's storage backend is PostgreSQL.
func IsPostgres(cfg *config.Config) bool {
	return cfg.Storage.Type == "postgres" || cfg.Storage.Type == "postgresql"
}

// Dir is the directory holding the journal: the database file's directory on
// SQLite, the first key-material file's directory on PostgreSQL (the same
// host-local anchor the rollback-protection witness uses there). "" when no
// restore can run against cfg (remote storage, or PostgreSQL with no key
// files configured).
func Dir(cfg *config.Config) (string, error) {
	switch {
	case cfg.Storage.Type == "local" || cfg.Storage.Type == "sqlite":
		dbPath := cfg.Storage.Database.Path
		if dbPath == "" {
			dbPath = "./secrets.db"
		}
		return filepath.Dir(dbPath), nil
	case IsPostgres(cfg):
		specs, err := keyfiles.Registry(&cfg.Storage.Encryption, ".")
		if err != nil {
			return "", fmt.Errorf("build key-file registry: %w", err)
		}
		if len(specs) == 0 {
			return "", nil
		}
		return filepath.Dir(specs[0].Path), nil
	default:
		return "", nil
	}
}

// Path is the journal's full path for cfg, "" when Dir is "".
func Path(cfg *config.Config) (string, error) {
	dir, err := Dir(cfg)
	if err != nil || dir == "" {
		return "", err
	}
	return filepath.Join(dir, FileName), nil
}

// Read returns the journal at path; found is false when there is none. A
// journal that exists but does not parse is an error, never "absent".
func Read(path string) (j Journal, found bool, err error) {
	data, err := os.ReadFile(path) // #nosec G304 -- Path(cfg): a config-derived directory plus a constant name
	if errors.Is(err, os.ErrNotExist) {
		return Journal{}, false, nil
	}
	if err != nil {
		return Journal{}, false, fmt.Errorf("read restore journal %q: %w", path, err)
	}
	if err := json.Unmarshal(data, &j); err != nil {
		return Journal{}, true, fmt.Errorf("restore journal %q does not parse: %w", path, err)
	}
	if j.Version != Version {
		return Journal{}, true, fmt.Errorf("restore journal %q has version %d, this binary reads version %d", path, j.Version, Version)
	}
	return j, true, nil
}

// Write durably creates the journal at path (temp file, fsync, rename, fsync
// of the directory): once Write returns, a crash cannot lose it.
func Write(path string, j Journal) error {
	j.Version = Version
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return fmt.Errorf("encode restore journal: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, FileName+".tmp-*")
	if err != nil {
		return fmt.Errorf("create restore journal: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) //nolint:errcheck // no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write restore journal: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync restore journal: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close restore journal: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("install restore journal: %w", err)
	}
	return SyncDir(dir)
}

// Remove deletes the journal at path and fsyncs its directory.
func Remove(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove restore journal %q: %w", path, err)
	}
	return SyncDir(filepath.Dir(path))
}

// RefuseIfPresent fails when cfg has an interrupted restore's journal: the
// key files and the data may come from different points in time until
// `admin restore --recover` resolves it, and starting on them can make
// secrets unreadable or encrypt new ones under the wrong key.
func RefuseIfPresent(cfg *config.Config) error {
	path, err := Path(cfg)
	if err != nil || path == "" {
		return err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("check for an interrupted restore journal %q: %w", path, err)
	}
	return fmt.Errorf("an interrupted `admin restore` left its journal at %s: the key files and the database may not "+
		"match until it is resolved. Stop every server on this data, then run `keyorix-server admin restore --recover` "+
		"(it finishes the restore if its data was committed, and undoes it otherwise)", path)
}

// SyncDir fsyncs a directory so a create, rename or remove in it survives a
// crash.
func SyncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- the directory of a config-derived path
	if err != nil {
		return err
	}
	defer d.Close() //nolint:errcheck
	return d.Sync()
}

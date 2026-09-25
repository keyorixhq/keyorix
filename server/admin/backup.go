// backup.go implements `keyorix-server admin backup` (ADR-108 §B3): a
// consistent, offline snapshot of the database and every encryption
// key-material file, taken while this admin command holds the database
// exclusively (acquireDatabaseLock) -- the same "operations that need the
// database to themselves" guarantee every other admin command relies on.
//
// A complete backup is TWO things -- the database and the keys -- matching
// docs/SELF_HOSTING.md §5's existing manual guidance for the Docker/Postgres
// deployment shape; this command is the single-binary/SQLite equivalent,
// scoped to local/sqlite storage only. Postgres support is explicitly out of
// scope here (refused loudly, not silently mishandled) -- see the error
// message for the existing manual pg_dump path.
package admin

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/spf13/cobra"
)

// backupFormatVersion guards forward compatibility: a backup taken by a
// newer binary with a format this binary's restore does not understand must
// refuse explicitly, not misinterpret the archive.
const backupFormatVersion = 1

// backupManifest is the archive's MANIFEST.json -- everything admin restore
// needs to validate an archive before touching disk: what backend it is for,
// which files it contains, and a checksum for each so a corrupted artifact
// is caught before it overwrites anything. A plain checksum like this is
// integrity, not authenticity: anyone who can edit the archive can
// recompute it to match, so it does not by itself prove the archive was not
// tampered with -- see restore.go's verifyRestoredAudit for the step that
// actually can.
type backupManifest struct {
	FormatVersion int               `json:"format_version"`
	CreatedAt     time.Time         `json:"created_at"`
	Backend       string            `json:"backend"` // always "sqlite" today
	DBFile        backupFileEntry   `json:"db_file"`
	KeyFiles      []backupFileEntry `json:"key_files"`
}

// backupFileEntry describes one file bundled into the archive: where it came
// from (also where restore writes it back to, by default), its tar member
// name, and enough to verify it wasn't corrupted in transit (see
// backupManifest's own doc comment on what a checksum does not prove).
type backupFileEntry struct {
	OriginalPath string `json:"original_path"`
	TarName      string `json:"tar_name"`
	Mode         uint32 `json:"mode"`
	SHA256       string `json:"sha256"`
	Size         int64  `json:"size"`
}

var backupOutput string

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Create a consistent offline backup of the database and encryption keys",
	Long: `Writes a single archive (--output) containing a consistent snapshot of the
configured database AND every encryption key-material file
(internal/keyfiles.Registry -- the same enumeration 'admin audit' checks).
Neither alone is a usable backup: the database without the keys is
unreadable ciphertext, the keys without the database are useless.

The database snapshot uses SQLite's VACUUM INTO, which produces a fully
consistent, standalone copy regardless of journal mode -- no external tool
required. Consistency is guaranteed by the same exclusive database lock
every admin command takes: no server (or other admin command) can be
writing while this runs.

Only local/sqlite storage is supported today. For a Postgres-backed
deployment, back up with pg_dump directly (see docs/SELF_HOSTING.md §5).

--output must not already exist: each backup is a distinct, timestamped
artifact. Store it OFF this host -- a backup that never leaves the machine
it was taken on protects against nothing.

Restore with: keyorix-server admin restore --input <archive>`,
	RunE: runAdminBackup,
}

func init() {
	backupCmd.Flags().StringVar(&backupOutput, "output", "", "Path to write the backup archive to (must not already exist; required)")
	rootCmd.AddCommand(backupCmd)
}

func runAdminBackup(cmd *cobra.Command, args []string) error {
	if backupOutput == "" {
		return fmt.Errorf("--output is required")
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.Storage.Type != "local" && cfg.Storage.Type != "sqlite" {
		return fmt.Errorf("admin backup only supports local/sqlite storage today (got %q) -- "+
			"for Postgres, back up with pg_dump directly (see docs/SELF_HOSTING.md §5)", cfg.Storage.Type)
	}

	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck

	manifest := backupManifest{
		FormatVersion: backupFormatVersion,
		CreatedAt:     time.Now().UTC(),
		Backend:       "sqlite",
	}

	dbEntry, dbBytes, err := snapshotSQLiteDatabase(cfg)
	if err != nil {
		return fmt.Errorf("snapshot database: %w", err)
	}
	manifest.DBFile = dbEntry

	specs, err := keyfiles.Registry(&cfg.Storage.Encryption, ".")
	if err != nil {
		return fmt.Errorf("build key-file registry: %w", err)
	}
	keyBlobs := make([][]byte, len(specs))
	for i, spec := range specs {
		data, rerr := os.ReadFile(spec.Path) // #nosec G304 -- config-driven path, sanitized by keyfiles.SafePath
		if rerr != nil {
			return fmt.Errorf("read key file %q: %w", spec.Path, rerr)
		}
		sum := sha256.Sum256(data)
		manifest.KeyFiles = append(manifest.KeyFiles, backupFileEntry{
			OriginalPath: spec.Path,
			TarName:      fmt.Sprintf("keyfiles/%d", i),
			Mode:         uint32(spec.Mode),
			SHA256:       hex.EncodeToString(sum[:]),
			Size:         int64(len(data)),
		})
		keyBlobs[i] = data
	}

	if err := writeBackupArchive(backupOutput, manifest, dbBytes, keyBlobs); err != nil {
		return err
	}

	fmt.Printf("Backup written to %s (database %d bytes, %d key file(s))\n", backupOutput, len(dbBytes), len(specs))
	fmt.Println("Store this archive OFF this host. Restore with:")
	fmt.Printf("  keyorix-server admin restore --input %s\n", backupOutput)

	recordAdminAction(cfg, "admin.backup_created",
		fmt.Sprintf("created backup archive %s (database %d bytes, %d key file(s))", backupOutput, len(dbBytes), len(specs)), true)
	return nil
}

// snapshotSQLiteDatabase opens the configured database via the SAME
// storage.OpenGormDB every other raw-DB admin path uses (DSN construction,
// permission tightening) and takes a consistent snapshot via VACUUM INTO --
// SQLite's own built-in equivalent of pg_dump, safe here because the caller
// already holds the exclusive database lock for the duration.
func snapshotSQLiteDatabase(cfg *config.Config) (backupFileEntry, []byte, error) {
	gdb, err := storage.OpenGormDB(cfg)
	if err != nil {
		return backupFileEntry{}, nil, err
	}
	defer closeGormDB(gdb)

	sqlDB, err := gdb.DB()
	if err != nil {
		return backupFileEntry{}, nil, fmt.Errorf("get raw db handle: %w", err)
	}
	// The configured DSN enables WAL mode (internal/storage/factory.go's
	// sqliteDSN). GORM's pool can hand VACUUM INTO a different physical
	// connection than whichever one most recently wrote -- pin this handle to
	// exactly one connection so there is no cross-connection WAL-visibility
	// question, and force a full checkpoint first so every committed page is
	// in the main db file before the snapshot reads it (found the hard way:
	// without this, VACUUM INTO's own output occasionally failed SQLite's
	// integrity check on the very next open).
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	if _, err := sqlDB.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return backupFileEntry{}, nil, fmt.Errorf("checkpoint WAL before snapshot: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "keyorix-admin-backup-*")
	if err != nil {
		return backupFileEntry{}, nil, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir) //nolint:errcheck

	// VACUUM INTO requires the destination to not already exist -- MkdirTemp
	// above only creates the directory, not this file, so the path is free.
	tmpPath := filepath.Join(tmpDir, "snapshot.db")
	if _, err := sqlDB.Exec("VACUUM INTO ?", tmpPath); err != nil {
		return backupFileEntry{}, nil, fmt.Errorf("VACUUM INTO snapshot: %w", err)
	}

	if err := verifySQLiteIntegrity(tmpPath); err != nil {
		return backupFileEntry{}, nil, fmt.Errorf("snapshot failed its own integrity check: %w", err)
	}

	data, err := os.ReadFile(tmpPath) // #nosec G304 -- our own just-created temp file
	if err != nil {
		return backupFileEntry{}, nil, fmt.Errorf("read snapshot: %w", err)
	}

	dbPath := cfg.Storage.Database.Path
	if dbPath == "" {
		dbPath = "./secrets.db"
	}
	sum := sha256.Sum256(data)
	return backupFileEntry{
		OriginalPath: dbPath,
		TarName:      "db.sqlite",
		Mode:         0600,
		SHA256:       hex.EncodeToString(sum[:]),
		Size:         int64(len(data)),
	}, data, nil
}

// verifySQLiteIntegrity opens path with a FRESH, independent connection
// (never the one that wrote it) and runs PRAGMA integrity_check -- catching
// a corrupt snapshot at backup time, loudly, instead of only discovering it
// later when a restore fails on a host that may no longer have the original
// database to re-back-up from.
func verifySQLiteIntegrity(path string) error {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return fmt.Errorf("open snapshot for integrity check: %w", err)
	}
	defer db.Close() //nolint:errcheck

	var result string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&result); err != nil {
		return fmt.Errorf("run integrity check: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("integrity_check reported: %s", result)
	}
	return nil
}

// writeBackupArchive writes manifest/dbBytes/keyBlobs as a gzipped tar to
// outputPath. O_EXCL: each backup is a distinct artifact -- silently
// overwriting a prior one would defeat the whole point of taking it. Any
// failure partway through removes the partial file rather than leaving a
// corrupt archive that looks complete.
func writeBackupArchive(outputPath string, manifest backupManifest, dbBytes []byte, keyBlobs [][]byte) error {
	f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600) // #nosec G304 -- operator-supplied output path, the whole point of this flag
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("--output %q already exists -- each backup is a distinct artifact, pick a new path (e.g. include a timestamp)", outputPath)
		}
		return fmt.Errorf("create %q: %w", outputPath, err)
	}

	if err := writeBackupArchiveContents(f, manifest, dbBytes, keyBlobs); err != nil {
		_ = f.Close()
		_ = os.Remove(outputPath)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(outputPath)
		return fmt.Errorf("close %q: %w", outputPath, err)
	}
	return nil
}

func writeBackupArchiveContents(f *os.File, manifest backupManifest, dbBytes []byte, keyBlobs [][]byte) error {
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode manifest: %w", err)
	}
	if err := writeTarEntry(tw, "MANIFEST.json", manifestJSON); err != nil {
		return err
	}
	if err := writeTarEntry(tw, manifest.DBFile.TarName, dbBytes); err != nil {
		return err
	}
	for i, blob := range keyBlobs {
		if err := writeTarEntry(tw, manifest.KeyFiles[i].TarName, blob); err != nil {
			return err
		}
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar writer: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("close gzip writer: %w", err)
	}
	return nil
}

func writeTarEntry(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name: name,
		Mode: 0600,
		Size: int64(len(data)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("write tar header %q: %w", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("write tar entry %q: %w", name, err)
	}
	return nil
}

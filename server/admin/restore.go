// restore.go implements `keyorix-server admin restore` (ADR-108 §B3): the
// other half of admin backup. Writes the database and every encryption
// key-material file back from an archive backup.go created, then applies
// pending migrations the same way `admin migrate` does -- covering the
// "version-skipping upgrade" case ADR-108 §B3 names alongside backup/restore:
// restoring an old backup onto a newer binary must leave the database ready
// to boot, not merely restored to its old schema.
//
// Refuses, rather than silently overwriting, an existing non-empty database
// or key file unless --overwrite-existing is given -- restoring into
// existing data is exactly the "trade loud failure for silent data loss"
// mistake this repo's engineering practices call out.
package admin

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/spf13/cobra"
)

var (
	restoreInput             string
	restoreOverwriteExisting bool
)

var restoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore the database and encryption keys from a backup archive created by `admin backup`",
	Long: `Restores the database and every encryption key-material file from an archive
'admin backup' created, then applies any pending migration the same way
'admin migrate' does -- so an old backup restored under a newer binary ends
up ready to start, not merely restored to its old schema.

Every file in the archive is checksum-verified before anything is written,
and the archive's key-file set must match this config's encryption settings
exactly (internal/keyfiles.Registry) -- a partial or mismatched key-file
restore would leave the database permanently undecryptable.

Refuses to overwrite an existing, non-empty database or key file unless
--overwrite-existing is given. Restore into a fresh/empty data dir with the
SAME config (same key-material paths) the backup was taken from.

Only local/sqlite storage is supported today. For a Postgres-backed
deployment, restore with psql directly (see docs/SELF_HOSTING.md §5).`,
	RunE: runAdminRestore,
}

func init() {
	restoreCmd.Flags().StringVar(&restoreInput, "input", "", "Path to the backup archive to restore from (required)")
	restoreCmd.Flags().BoolVar(&restoreOverwriteExisting, "overwrite-existing", false, "Overwrite an existing, non-empty database or key file (dangerous)")
	rootCmd.AddCommand(restoreCmd)
}

func runAdminRestore(cmd *cobra.Command, args []string) error {
	if restoreInput == "" {
		return fmt.Errorf("--input is required")
	}

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.Storage.Type != "local" && cfg.Storage.Type != "sqlite" {
		return fmt.Errorf("admin restore only supports local/sqlite storage today (got %q) -- "+
			"for Postgres, restore with psql directly (see docs/SELF_HOSTING.md §5)", cfg.Storage.Type)
	}

	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck

	manifest, dbBytes, keyBlobs, err := readBackupArchive(restoreInput)
	if err != nil {
		return fmt.Errorf("read backup archive %q: %w", restoreInput, err)
	}
	if manifest.FormatVersion != backupFormatVersion {
		return fmt.Errorf("backup archive format version %d is not supported by this binary (supports version %d)",
			manifest.FormatVersion, backupFormatVersion)
	}
	if manifest.Backend != "sqlite" {
		return fmt.Errorf("backup archive is for backend %q, this config is sqlite -- restore refuses to mix backends", manifest.Backend)
	}

	dbPath := cfg.Storage.Database.Path
	if dbPath == "" {
		dbPath = "./secrets.db"
	}
	if err := refuseNonEmptyExisting("database", dbPath); err != nil {
		return err
	}

	targetKeyPaths, err := expectedKeyFilePaths(cfg)
	if err != nil {
		return err
	}
	if err := validateKeyFileSet(manifest.KeyFiles, targetKeyPaths); err != nil {
		return err
	}

	if err := verifyChecksum(manifest.DBFile, dbBytes); err != nil {
		return err
	}
	for i, entry := range manifest.KeyFiles {
		if err := verifyChecksum(entry, keyBlobs[i]); err != nil {
			return err
		}
		if err := refuseNonEmptyExisting("key file", entry.OriginalPath); err != nil {
			return err
		}
	}

	for i, entry := range manifest.KeyFiles {
		if err := writeRestoredFile(entry.OriginalPath, keyBlobs[i], os.FileMode(entry.Mode)); err != nil {
			return fmt.Errorf("write key file %q: %w", entry.OriginalPath, err)
		}
	}
	// A previous WAL-mode database at this exact path (internal/storage/
	// factory.go's sqliteDSN always enables WAL) can leave <dbPath>-wal/-shm
	// sidecars behind even after dbPath itself was removed -- they are not
	// content, only replay/shared-memory state FOR the specific main-file
	// generation that wrote them. VACUUM INTO's snapshot is plain (non-WAL)
	// by construction, so any sidecar still sitting next to the target path
	// belongs to a DIFFERENT database generation than the bytes about to be
	// written; leaving it in place makes SQLite try to replay a WAL that does
	// not correspond to the restored file, which surfaces as "database disk
	// image is malformed" the first time anything queries it -- found via a
	// direct repro (VACUUM INTO's own output passed PRAGMA integrity_check
	// every time; only the WAL-mode reopen after a same-path restore failed,
	// and only when a stale sidecar was still present).
	if err := removeStaleSQLiteSidecars(dbPath); err != nil {
		return fmt.Errorf("clear stale WAL sidecar files for %q: %w", dbPath, err)
	}
	if err := writeRestoredFile(dbPath, dbBytes, os.FileMode(manifest.DBFile.Mode)); err != nil {
		return fmt.Errorf("write database %q: %w", dbPath, err)
	}

	fmt.Println("Applying pending migrations to the restored database (idempotent)...")
	if _, err := storage.NewStorageFactory().CreateStorage(cfg); err != nil {
		return fmt.Errorf("migrate restored database: %w", err)
	}

	fmt.Printf("Restored database (%d bytes) and %d key file(s) from %s (backup created %s)\n",
		len(dbBytes), len(manifest.KeyFiles), restoreInput, manifest.CreatedAt.Format(time.RFC3339))
	fmt.Println("Run 'keyorix-server admin diagnose' and 'keyorix-server admin verify-audit' to confirm the restore.")

	recordAdminAction(cfg, "admin.restore_completed",
		fmt.Sprintf("restored from backup archive %s (created %s)", restoreInput, manifest.CreatedAt.Format(time.RFC3339)), true)
	return nil
}

// expectedKeyFilePaths re-derives the CURRENT (restore-target) config's
// key-material paths via the same registry `admin audit`/`admin backup` use.
// keyfiles.Registry's required entries (salt, DEK, provider wrapped-key,
// shamir shares) are included unconditionally regardless of whether the file
// currently exists on disk -- exactly what a fresh/empty data dir needs.
func expectedKeyFilePaths(cfg *config.Config) ([]string, error) {
	specs, err := keyfiles.Registry(&cfg.Storage.Encryption, ".")
	if err != nil {
		return nil, fmt.Errorf("build key-file registry: %w", err)
	}
	paths := make([]string, len(specs))
	for i, s := range specs {
		paths[i] = s.Path
	}
	return paths, nil
}

// validateKeyFileSet refuses a partial or mismatched key-file restore (e.g.
// a backup taken mid key-rotation, with a ".pending" sibling this config no
// longer expects) instead of silently dropping or misplacing a file --
// either would leave the restored database undecryptable in a way that only
// surfaces later, at the worst possible time.
func validateKeyFileSet(archived []backupFileEntry, target []string) error {
	if len(archived) != len(target) {
		return fmt.Errorf("backup archive has %d key file(s) but this config's encryption settings expect %d -- "+
			"restore refuses a partial/mismatched key-file set", len(archived), len(target))
	}
	for i, entry := range archived {
		if entry.OriginalPath != target[i] {
			return fmt.Errorf("backup archive's key file #%d is for path %q, this config expects %q -- "+
				"restore refuses a mismatched key-file set (restore into the same config the backup was taken from)",
				i, entry.OriginalPath, target[i])
		}
	}
	return nil
}

func verifyChecksum(entry backupFileEntry, data []byte) error {
	if int64(len(data)) != entry.Size {
		return fmt.Errorf("archive entry %q failed integrity check (size mismatch: got %d, want %d) -- "+
			"the backup file may be corrupted or tampered with", entry.TarName, len(data), entry.Size)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != entry.SHA256 {
		return fmt.Errorf("archive entry %q failed integrity check (checksum mismatch) -- "+
			"the backup file may be corrupted or tampered with", entry.TarName)
	}
	return nil
}

// removeStaleSQLiteSidecars removes dbPath's WAL-mode sidecar files
// (-wal, -shm) if present. Best-effort existence-based removal: absent is
// the common/expected case (a genuinely fresh data dir), not an error.
func removeStaleSQLiteSidecars(dbPath string) error {
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(dbPath + suffix); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// refuseNonEmptyExisting is the "don't trade loud failure for silent data
// loss" guard: a missing or genuinely-empty (0-byte, e.g. `admin init
// --database` on a fresh dir) target is fine to write, but anything with
// actual content requires an explicit --overwrite-existing.
func refuseNonEmptyExisting(label, path string) error {
	if restoreOverwriteExisting {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil // does not exist (or another error writeRestoredFile will surface) -- fine to write
	}
	if info.Size() > 0 {
		return fmt.Errorf("%s %q already exists and is not empty -- restore refuses to overwrite it "+
			"(pass --overwrite-existing if you are certain, e.g. this is a genuine disaster-recovery restore; "+
			"the normal flow is restoring into a fresh/empty data dir)", label, path)
	}
	return nil
}

func writeRestoredFile(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}
	flags := os.O_CREATE | os.O_WRONLY
	if restoreOverwriteExisting {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_EXCL
	}
	// #nosec G304 -- path is either this config's own database path or one
	// returned by keyfiles.Registry (already SafePath-sanitized) and, for key
	// files, already matched 1:1 against the archive manifest by
	// validateKeyFileSet -- never an attacker-controlled path from the archive.
	f, err := os.OpenFile(path, flags, mode)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck
	if _, err := f.Write(data); err != nil {
		return err
	}
	return nil
}

// readBackupArchive parses a gzipped tar written by writeBackupArchive,
// requiring the manifest and every entry it references to be present before
// returning anything -- restore must never proceed on a partially-readable
// archive.
func readBackupArchive(path string) (backupManifest, []byte, [][]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied input path, the whole point of this flag
	if err != nil {
		return backupManifest{}, nil, nil, err
	}
	defer f.Close() //nolint:errcheck

	gz, err := gzip.NewReader(f)
	if err != nil {
		return backupManifest{}, nil, nil, fmt.Errorf("not a valid backup archive (gzip): %w", err)
	}
	defer gz.Close() //nolint:errcheck
	tr := tar.NewReader(gz)

	var manifest backupManifest
	manifestRead := false
	var dbBytes []byte
	keyBlobsByName := make(map[string][]byte)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return backupManifest{}, nil, nil, fmt.Errorf("read tar entry: %w", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return backupManifest{}, nil, nil, fmt.Errorf("read tar entry %q: %w", hdr.Name, err)
		}
		switch {
		case hdr.Name == "MANIFEST.json":
			if err := json.Unmarshal(data, &manifest); err != nil {
				return backupManifest{}, nil, nil, fmt.Errorf("parse manifest: %w", err)
			}
			manifestRead = true
		case hdr.Name == "db.sqlite":
			dbBytes = data
		case strings.HasPrefix(hdr.Name, "keyfiles/"):
			keyBlobsByName[hdr.Name] = data
		}
	}

	if !manifestRead {
		return backupManifest{}, nil, nil, fmt.Errorf("archive has no MANIFEST.json -- not a keyorix-server admin backup")
	}
	if dbBytes == nil {
		return backupManifest{}, nil, nil, fmt.Errorf("archive has no %s entry", manifest.DBFile.TarName)
	}
	keyBlobs := make([][]byte, len(manifest.KeyFiles))
	for i, entry := range manifest.KeyFiles {
		blob, ok := keyBlobsByName[entry.TarName]
		if !ok {
			return backupManifest{}, nil, nil, fmt.Errorf("archive manifest references %q but the archive has no such entry", entry.TarName)
		}
		keyBlobs[i] = blob
	}
	return manifest, dbBytes, keyBlobs, nil
}

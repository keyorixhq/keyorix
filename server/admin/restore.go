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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/spf13/cobra"
)

// restoreFileMode is the mode every restored file (database and key files
// alike) is written with, regardless of what the archive's own manifest
// records -- a crafted manifest must never be able to make a restored
// key/DB file group- or world-readable. See writeRestoredFile.
const restoreFileMode = 0600

// defaultMaxRestoreEntryBytes/defaultMaxRestoreTotalBytes bound how much
// decompressed data readBackupArchive will hold in memory for a single tar
// entry, and across the whole archive, before refusing it -- an archive
// (gzip+tar) can decompress to far more bytes than it occupies on disk, and
// an operator restoring from removable/untrusted media has no independent
// way to know an archive is hostile before restore reads it. 1 GiB per file
// is generous headroom for a keyorix secrets database or key-material file;
// --max-entry-bytes/--max-total-bytes raise it for a legitimately larger
// deployment.
const (
	defaultMaxRestoreEntryBytes = 1 << 30
	defaultMaxRestoreTotalBytes = 2 * defaultMaxRestoreEntryBytes
)

var (
	restoreInput             string
	restoreOverwriteExisting bool
	restoreMaxEntryBytes     int64
	restoreMaxTotalBytes     int64
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
restore would leave the database permanently undecryptable. Checksums catch
CORRUPTION (a bad copy, a truncated transfer, bit rot) -- not TAMPERING:
anyone who can edit the archive can recompute them to match, so a passing
checksum is not proof the archive is authentic. Restore therefore also runs
'admin verify-audit' automatically against the restored database once
migrations are applied, and fails (non-zero exit) if it reports the audit
chain BROKEN -- tamper evidence comes from that hash chain, not the backup
manifest.

Each restored file is written atomically (temp file + fsync + rename into
the target directory, which is itself fsynced afterward), so a failure or
crash partway through never leaves a target file truncated or half-written.

Refuses to overwrite an existing, non-empty database or key file unless
--overwrite-existing is given. Restore into a fresh/empty data dir with the
SAME config (same key-material paths) the backup was taken from. With
--overwrite-existing, an existing file is renamed aside to
<path>.pre-restore-<timestamp> rather than truncated or overwritten in
place, so an unrecoverable mistake during the restore still has a way back.

Only local/sqlite storage is supported today. For a Postgres-backed
deployment, restore with psql directly (see docs/SELF_HOSTING.md §5).`,
	RunE: runAdminRestore,
}

func init() {
	restoreCmd.Flags().StringVar(&restoreInput, "input", "", "Path to the backup archive to restore from (required)")
	restoreCmd.Flags().BoolVar(&restoreOverwriteExisting, "overwrite-existing", false, "Overwrite an existing, non-empty database or key file (dangerous)")
	restoreCmd.Flags().Int64Var(&restoreMaxEntryBytes, "max-entry-bytes", defaultMaxRestoreEntryBytes,
		"Reject the archive if any single entry (the database or a key file) decompresses to more than this many bytes")
	restoreCmd.Flags().Int64Var(&restoreMaxTotalBytes, "max-total-bytes", defaultMaxRestoreTotalBytes,
		"Reject the archive if its total decompressed size across all entries exceeds this many bytes")
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

	manifest, dbBytes, keyBlobs, err := readBackupArchive(restoreInput, restoreMaxEntryBytes, restoreMaxTotalBytes)
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

	// One timestamp for the whole restore run, reused for every existing file
	// --overwrite-existing moves aside, so they're identifiable as belonging
	// to the same restore.
	restoreTS := time.Now().UTC().Format("20060102T150405Z")

	for i, entry := range manifest.KeyFiles {
		if err := writeRestoredFile(entry.OriginalPath, keyBlobs[i], restoreTS); err != nil {
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
	if err := writeRestoredFile(dbPath, dbBytes, restoreTS); err != nil {
		return fmt.Errorf("write database %q: %w", dbPath, err)
	}

	fmt.Println("Applying pending migrations to the restored database (idempotent)...")
	if _, err := storage.NewStorageFactory().CreateStorage(cfg); err != nil {
		return fmt.Errorf("migrate restored database: %w", err)
	}

	fmt.Printf("Restored database (%d bytes) and %d key file(s) from %s (backup created %s)\n",
		len(dbBytes), len(manifest.KeyFiles), restoreInput, manifest.CreatedAt.Format(time.RFC3339))
	fmt.Println("Run 'keyorix-server admin diagnose' to further confirm the restore.")

	recordAdminAction(cfg, "admin.restore_completed",
		fmt.Sprintf("restored from backup archive %s (created %s)", restoreInput, manifest.CreatedAt.Format(time.RFC3339)), true)

	return verifyRestoredAudit(cfg, dbPath)
}

// verifyRestoredAudit runs the same offline audit-chain re-walk
// `admin verify-audit` exposes as a standalone command, directly against the
// just-restored database file -- never through the config's normal
// server-guard-locked path, since this restore already holds that lock for
// its own duration (see acquireDatabaseLock above; a second acquisition
// attempt on the same config would just fail).
//
// verifyChecksum (above) only proves the archive was not CORRUPTED in
// transit -- anyone who can edit the archive can recompute its checksums to
// match, so it proves nothing about tampering. This is the step in restore
// that actually can detect the restored database was tampered with, by
// re-walking its ADR-029 audit hash chain -- run automatically so an
// operator doesn't have to remember to do it by hand. Only a BROKEN verdict
// fails restore (non-zero exit); VALID and INDETERMINATE are both reported
// but do not, matching verify-audit's own documented semantics (a bare
// re-walk with no --checkpoint-key-file cannot detect tail-truncation, and
// reports that as its own limit, not as BROKEN).
func verifyRestoredAudit(cfg *config.Config, dbPath string) error {
	db, err := auditverify.OpenSQLiteReadOnly(dbPath)
	if err != nil {
		return fmt.Errorf("open restored database for automatic verify-audit: %w", err)
	}
	defer db.Close() //nolint:errcheck

	var opts auditverify.Options
	if cfg.Audit.OfflineAnchorPath != "" {
		data, err := os.ReadFile(cfg.Audit.OfflineAnchorPath) // #nosec G304 -- operator-configured path (audit.offline_anchor_path)
		if err != nil {
			return fmt.Errorf("automatic verify-audit: read configured offline anchor %q: %w", cfg.Audit.OfflineAnchorPath, err)
		}
		bundle, err := auditverify.ParseExternalAnchorBundle(data)
		if err != nil {
			return fmt.Errorf("automatic verify-audit: parse configured offline anchor %q: %w", cfg.Audit.OfflineAnchorPath, err)
		}
		opts.ExternalAnchor = bundle
	}

	result, err := auditverify.Verify(context.Background(), db, opts)
	if err != nil {
		return fmt.Errorf("automatic verify-audit failed to run: %w", err)
	}

	fmt.Printf("verify-audit on the restored database: %s", result.Verdict)
	if result.Reason != "" {
		fmt.Printf(" (%s)", result.Reason)
	}
	fmt.Println()

	if result.Verdict == auditverify.VerdictBroken {
		return newExitCodeError(1, fmt.Errorf(
			"the restored database failed automatic audit-chain verification (%s) -- do not trust this restore; "+
				"run 'keyorix-server admin verify-audit' directly for the full report", result.Verdict))
	}
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

// writeRestoredFile atomically writes data to path: a temp file in the same
// directory is written, fsynced, and renamed (or, without --overwrite-
// existing, hard-linked -- see below) into place, so a crash or failure
// partway through never leaves path holding a truncated or half-written
// file. Always writes restoreFileMode (0600), never whatever mode the
// archive's manifest recorded -- a crafted manifest must never be able to
// make a restored key/DB file group- or world-readable.
//
// With --overwrite-existing, an existing file at path is renamed aside to
// "<path>.pre-restore-<restoreTS>" (never truncated or overwritten in
// place) before the new file is renamed in, so an unrecoverable mistake
// during an --overwrite-existing restore still has a way back. Without it,
// the new file is hard-linked into place instead of renamed: os.Link fails
// atomically with EEXIST if path already exists, closing the window between
// refuseNonEmptyExisting's earlier check and this write during which
// another process could have created path (os.Rename has no portable
// no-clobber option and would silently replace it).
func writeRestoredFile(path string, data []byte, restoreTS string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	// #nosec G304 -- path is either this config's own database path or one
	// returned by keyfiles.Registry (already SafePath-sanitized) and, for key
	// files, already matched 1:1 against the archive manifest by
	// validateKeyFileSet -- never an attacker-controlled path from the archive.
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".restoring-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	// No-op once renamed/linked into place below.
	defer os.Remove(tmpPath) //nolint:errcheck

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, restoreFileMode); err != nil {
		return fmt.Errorf("set file mode: %w", err)
	}

	if restoreOverwriteExisting {
		if _, err := os.Stat(path); err == nil {
			aside := fmt.Sprintf("%s.pre-restore-%s", path, restoreTS)
			if err := os.Rename(path, aside); err != nil {
				return fmt.Errorf("move existing %q aside to %q: %w", path, aside, err)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat %q: %w", path, err)
		}
		if err := os.Rename(tmpPath, path); err != nil {
			return fmt.Errorf("rename into place: %w", err)
		}
	} else {
		// Re-check immediately before linking (refuseNonEmptyExisting's own
		// check happened earlier, before any file in this restore was
		// written) -- a non-empty file here means something else created it
		// concurrently during this restore, not the archive being restored.
		if info, err := os.Stat(path); err == nil {
			if info.Size() > 0 {
				return fmt.Errorf("%q was created concurrently during restore and is not empty -- refusing to overwrite it", path)
			}
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("remove empty placeholder %q: %w", path, err)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat %q: %w", path, err)
		}
		if err := os.Link(tmpPath, path); err != nil {
			if os.IsExist(err) {
				return fmt.Errorf("%q was created concurrently during restore -- refusing to overwrite it", path)
			}
			return fmt.Errorf("link into place: %w", err)
		}
	}

	if err := fsyncDir(dir); err != nil {
		return fmt.Errorf("fsync directory %q: %w", dir, err)
	}
	return nil
}

// fsyncDir fsyncs a directory's own inode/entry list after a create, link,
// or rename within it -- otherwise the new directory entry pointing at the
// just-written, already-fsynced file can itself be lost on a crash, even
// though the file's own contents were durably synced.
func fsyncDir(dir string) error {
	// #nosec G304 -- dir is filepath.Dir() of writeRestoredFile's own path
	// argument, never attacker-controlled archive content (see that
	// function's own #nosec comment).
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close() //nolint:errcheck
	return d.Sync()
}

// readBackupArchive parses a gzipped tar written by writeBackupArchive,
// requiring the manifest and every entry it references to be present before
// returning anything -- restore must never proceed on a partially-readable
// archive. maxEntryBytes/maxTotalBytes (0 means "use the package default")
// bound how much decompressed data this will ever hold in memory, since the
// archive is operator-supplied input that may come from untrusted or
// removable media (a gzip+tar decompression bomb): every read is through
// io.LimitReader, never a bare io.ReadAll(tr).
//
// The first entry must be MANIFEST.json (matching writeBackupArchiveContents,
// which always writes it first) -- every other entry's declared size in that
// already-parsed manifest becomes ITS per-entry cap, and any entry whose name
// the manifest does not reference is rejected as soon as its header is seen,
// before its body is read at all. Every entry must be a regular file
// (rejecting symlinks/hardlinks/devices), and duplicate entry names are
// rejected.
func readBackupArchive(path string, maxEntryBytes, maxTotalBytes int64) (backupManifest, []byte, [][]byte, error) {
	if maxEntryBytes <= 0 {
		maxEntryBytes = defaultMaxRestoreEntryBytes
	}
	if maxTotalBytes <= 0 {
		maxTotalBytes = defaultMaxRestoreTotalBytes
	}

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
	seenNames := make(map[string]bool)
	var totalRead int64
	first := true

	// readCapped reads at most cap bytes of the current tar entry (never
	// more, regardless of what the entry claims to decompress to), and never
	// lets the running total across the whole archive exceed maxTotalBytes.
	readCapped := func(name string, limit int64) ([]byte, error) {
		remaining := maxTotalBytes - totalRead
		if remaining < 0 {
			remaining = 0
		}
		effLimit := limit
		if remaining < effLimit {
			effLimit = remaining
		}
		data, err := io.ReadAll(io.LimitReader(tr, effLimit+1))
		if err != nil {
			return nil, fmt.Errorf("read tar entry %q: %w", name, err)
		}
		if int64(len(data)) > effLimit {
			if effLimit < limit {
				return nil, fmt.Errorf("archive exceeds the %d-byte total decompressed size limit (--max-total-bytes)", maxTotalBytes)
			}
			return nil, fmt.Errorf("archive entry %q exceeds the %d-byte per-entry size limit (--max-entry-bytes)", name, limit)
		}
		totalRead += int64(len(data))
		return data, nil
	}

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return backupManifest{}, nil, nil, fmt.Errorf("read tar entry: %w", err)
		}

		if hdr.Typeflag != tar.TypeReg {
			return backupManifest{}, nil, nil, fmt.Errorf(
				"archive entry %q is not a regular file (tar type %q) -- restore refuses non-regular entries",
				hdr.Name, string(hdr.Typeflag))
		}
		if seenNames[hdr.Name] {
			return backupManifest{}, nil, nil, fmt.Errorf("archive contains a duplicate entry %q", hdr.Name)
		}
		seenNames[hdr.Name] = true

		if first {
			first = false
			if hdr.Name != "MANIFEST.json" {
				return backupManifest{}, nil, nil, fmt.Errorf(
					"archive's first entry is %q, expected MANIFEST.json -- not a keyorix-server admin backup", hdr.Name)
			}
			data, err := readCapped(hdr.Name, maxEntryBytes)
			if err != nil {
				return backupManifest{}, nil, nil, err
			}
			if err := json.Unmarshal(data, &manifest); err != nil {
				return backupManifest{}, nil, nil, fmt.Errorf("parse manifest: %w", err)
			}
			manifestRead = true
			continue
		}

		entry, ok := manifestEntryFor(manifest, hdr.Name)
		if !ok {
			return backupManifest{}, nil, nil, fmt.Errorf(
				"archive contains entry %q, which is not referenced by its own MANIFEST.json -- restore refuses unlisted entries", hdr.Name)
		}
		if entry.Size < 0 || entry.Size > maxEntryBytes {
			return backupManifest{}, nil, nil, fmt.Errorf(
				"archive manifest declares %q at %d bytes, exceeding the %d-byte per-entry limit (--max-entry-bytes)",
				hdr.Name, entry.Size, maxEntryBytes)
		}
		data, err := readCapped(hdr.Name, entry.Size)
		if err != nil {
			return backupManifest{}, nil, nil, err
		}
		if hdr.Name == manifest.DBFile.TarName {
			dbBytes = data
		} else {
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

// manifestEntryFor looks up the backupFileEntry a tar entry name corresponds
// to (the database file, or one of the key files) in an already-parsed
// manifest -- used both for each entry's declared (and therefore capped)
// size, and to reject any tar entry the manifest does not reference.
func manifestEntryFor(manifest backupManifest, tarName string) (backupFileEntry, bool) {
	if tarName == manifest.DBFile.TarName {
		return manifest.DBFile, true
	}
	for _, kf := range manifest.KeyFiles {
		if tarName == kf.TarName {
			return kf, true
		}
	}
	return backupFileEntry{}, false
}

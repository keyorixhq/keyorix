// restore.go implements `keyorix-server admin restore` (ADR-108 §B3,
// design-b3-backup-v2.md): the other half of admin backup. Dispatches on
// the archive's own declared format_version: v2 (backupfmt, the only format
// `admin backup` writes now) is the normal path; v1 (physical, SQLite-only,
// #2099) is read-only-supported until Keyorix 1.0 (design §3.6 decision 3),
// implemented in backup_v1_legacy.go's readBackupArchive plus this file's
// runAdminRestoreV1.
//
// Refuses, rather than silently overwriting, an existing non-empty database
// or key file unless --overwrite-existing is given -- restoring into
// existing data is exactly the "trade loud failure for silent data loss"
// mistake this repo's engineering practices call out.
package admin

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/backupfmt"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/restorejournal"
	"github.com/keyorixhq/keyorix/internal/secretenv"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

// restoreFileMode is the mode every restored file (database and key files
// alike) is written with, regardless of what the archive's own manifest
// records -- a crafted manifest must never be able to make a restored
// key/DB file group- or world-readable. See writeRestoredFile.
const restoreFileMode = 0600

// defaultMaxRestoreEntryBytes/defaultMaxRestoreTotalBytes bound how much
// decompressed data restore will hold (per staged file, and in total) before
// refusing an archive -- an archive (gzip+tar) can decompress to far more
// bytes than it occupies on disk, and an operator restoring from
// removable/untrusted media has no independent way to know an archive is
// hostile before restore reads it. 1 GiB per file is generous headroom for
// a keyorix secrets database table or key-material file;
// --max-entry-bytes/--max-total-bytes raise it for a legitimately larger
// deployment.
const (
	defaultMaxRestoreEntryBytes = 1 << 30
	defaultMaxRestoreTotalBytes = 2 * defaultMaxRestoreEntryBytes
)

var (
	restoreInput             string
	restoreOverwriteExisting bool
	restoreAllowRollback     bool
	restoreMaxEntryBytes     int64
	restoreMaxTotalBytes     int64
	restorePassphraseSource  crypto.PassphraseSource
)

var restoreCmd = &cobra.Command{
	Use:   "restore",
	Short: "Restore the database and encryption keys from a backup archive created by `admin backup`",
	Long: `Restores the database and every encryption key-material file from an archive
'admin backup' created, then applies any pending migration the same way
'admin migrate' does -- so an old backup restored under a newer binary ends
up ready to start, not merely restored to its old schema.

The archive's manifest is signature-verified (HMAC-SHA256, KEK-derived key)
BEFORE any byte reaches the real target -- an
authenticity check a plain checksum cannot provide, since anyone who can
edit the archive can recompute a checksum to match. Restore also runs
'admin verify-audit' automatically against the restored database once
migrations are applied, and fails (non-zero exit) if it reports the audit
chain BROKEN.

Each restored file is written atomically (temp file + fsync + rename into
the target directory, which is itself fsynced afterward), so a failure or
crash partway through never leaves a target file truncated or half-written.

The key files and the data are installed together or not at all: the
archive's key files are staged next to their targets, the data is loaded
(PostgreSQL: one transaction; SQLite: into a staged database file), and only
once that load has committed are the staged key files (and the SQLite file)
renamed into place. A restore that fails before that point leaves the live
key files and data exactly as they were. One killed after it leaves a
restore journal (.keyorix-restore-journal.json, next to the SQLite database
or the first key file): the server and 'admin backup' refuse to run until
'admin restore --recover' finishes the restore (data committed) or undoes it
(data not committed).

Refuses to overwrite an existing, non-empty database or key file unless
--overwrite-existing is given. Restore into a fresh/empty data dir with the
SAME config (same key-material paths) the backup was taken from. With
--overwrite-existing, an existing file is renamed aside to
<path>.pre-restore-<timestamp> rather than truncated or overwritten in
place, so an unrecoverable mistake during the restore still has a way back;
on PostgreSQL the target's tables are emptied inside the load transaction.

Rollback protection: restoring an OLDER backup
than this host has already progressed past can silently resurrect access an
admin has since revoked (a suspended account, a deleted machine credential,
a rotated role grant) -- the restored database simply doesn't know the
revocation happened. Restore compares the archive's own certified audit
high-water mark against a host-local witness file
(<data-dir>/.audit-highwater-witness, sibling to the database, maintained by
every server this host has run) BEFORE writing anything to disk, and refuses
if the archive is behind. Pass --allow-rollback for a genuine disaster-
recovery restore of an intentionally older backup -- this writes an audit
event to the restored database recording exactly how far back the restore
went, once the chain is writable again.

An archive taken under the old (v1, pre-2026-09-28) physical/SQLite-only
format still restores, with a deprecation notice -- take a fresh backup
under the current format when convenient (a v1 archive can only be restored
into SQLite). The target may be SQLite or PostgreSQL, whichever backend the
config points at, regardless of the backend the v2 archive came from; for
PostgreSQL the target database must already exist, and be empty unless
--overwrite-existing is given.`,
	RunE: runAdminRestore,
}

func init() {
	restoreCmd.Flags().StringVar(&restoreInput, "input", "", "Path to the backup archive to restore from (required)")
	restoreCmd.Flags().BoolVar(&restoreOverwriteExisting, "overwrite-existing", false, "Overwrite an existing, non-empty database or key file (dangerous)")
	restoreCmd.Flags().BoolVar(&restoreAllowRollback, "allow-rollback", false, "Proceed even though this backup is behind this host's own audit trail (dangerous -- see the rollback-protection note above)")
	restoreCmd.Flags().Int64Var(&restoreMaxEntryBytes, "max-entry-bytes", defaultMaxRestoreEntryBytes,
		"Reject the archive if any single entry decompresses to more than this many bytes")
	restoreCmd.Flags().Int64Var(&restoreMaxTotalBytes, "max-total-bytes", defaultMaxRestoreTotalBytes,
		"Reject the archive if its total decompressed size across all entries exceeds this many bytes")
	restoreCmd.Flags().BoolVar(&restoreRecover, "recover", false,
		"Resolve a restore that was interrupted (process killed, power loss) after it started installing: finish it if its data was committed, undo it otherwise")
	registerPassphraseFlags(restoreCmd, &restorePassphraseSource)
	rootCmd.AddCommand(restoreCmd)
}

func runAdminRestore(cmd *cobra.Command, args []string) error {
	if restoreInput == "" && !restoreRecover {
		return fmt.Errorf("--input is required")
	}
	restorePassphrase = &passphraseOnce{src: restorePassphraseSource}
	defer restorePassphrase.wipe()

	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.Storage.Type != "local" && cfg.Storage.Type != "sqlite" && !isPostgresStorage(cfg) {
		return fmt.Errorf("admin restore does not support storage type %q", cfg.Storage.Type)
	}

	lock, err := acquireDatabaseLock(cfg)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck

	if restoreRecover {
		return runAdminRestoreRecover(cfg)
	}
	if err := restorejournal.RefuseIfPresent(cfg); err != nil {
		return err
	}
	if !forceFlag {
		// No journal: any staged file beside the live ones is an orphan of a
		// restore killed before it wrote one (never under --force, which may
		// run beside another command holding the lock).
		if err := removeOrphanStagedFiles(cfg); err != nil {
			return err
		}
	}

	version, err := peekFormatVersion(restoreInput)
	if err != nil {
		return fmt.Errorf("read backup archive %q: %w", restoreInput, err)
	}
	switch version {
	case backupFormatVersion: // 1
		fmt.Println("NOTE: this archive uses the deprecated v1 (physical, pre-2026-09-28) backup format -- " +
			"it still restores, but take a fresh backup under the current format when convenient.")
		return runAdminRestoreV1(cfg)
	case backupfmt.FormatVersion: // 2
		return runAdminRestoreV2(cfg)
	default:
		return fmt.Errorf("backup archive format version %d is not supported by this binary (supports version %d or %d)",
			version, backupFormatVersion, backupfmt.FormatVersion)
	}
}

// peekFormatVersion reads just enough of the archive (its first tar entry,
// which must be MANIFEST.json in either format) to learn which format
// reader to dispatch to -- both backupManifest (v1) and backupfmt.Manifest
// (v2) declare format_version as their first JSON field, at the same
// top-level position, so this generic probe works against either without
// needing to know which one it's looking at yet.
func peekFormatVersion(path string) (int, error) {
	f, err := secretenv.OpenRegularNamed("backup archive", path) // operator-supplied input path; a FIFO is refused, not waited on
	if err != nil {
		return 0, err
	}
	defer f.Close() //nolint:errcheck

	gz, err := gzip.NewReader(f)
	if err != nil {
		return 0, fmt.Errorf("not a valid backup archive (gzip): %w", err)
	}
	defer gz.Close() //nolint:errcheck
	tr := tar.NewReader(gz)

	hdr, err := tr.Next()
	if err != nil {
		return 0, fmt.Errorf("read tar entry: %w", err)
	}
	if hdr.Name != "MANIFEST.json" {
		return 0, fmt.Errorf("archive's first entry is %q, expected MANIFEST.json -- not a keyorix-server admin backup", hdr.Name)
	}
	// A generous but bounded cap for the peek alone -- the real per-format
	// reader (readBackupArchive or ExtractArchive) re-applies the
	// operator-configured --max-entry-bytes immediately after this returns.
	data, err := io.ReadAll(io.LimitReader(tr, 64<<20))
	if err != nil {
		return 0, fmt.Errorf("read manifest: %w", err)
	}
	var probe struct {
		FormatVersion int `json:"format_version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return 0, fmt.Errorf("parse manifest: %w", err)
	}
	return probe.FormatVersion, nil
}

// saturatingQuadruple returns n*4, clamped to math.MaxInt64 rather than
// silently overflowing into a negative int64 -- archiveInfo.Size() is a real
// file's size and realistically nowhere near this range on any filesystem
// today, but CheckFreeSpace's own fail-closed guarantee (internal/backupfmt/
// preflight.go) is only as good as what its caller hands it, and a negative
// requiredBytes here would otherwise reach CheckFreeSpace's own refusal for
// a different, confusing reason.
func saturatingQuadruple(n int64) int64 {
	if n < 0 || n > math.MaxInt64/4 {
		return math.MaxInt64
	}
	return n * 4
}

// runAdminRestoreV2 is the current (design-b3-backup-v2.md) restore path.
func runAdminRestoreV2(cfg *config.Config) error { // NOSONAR -- cognitive complexity, orchestrates §5.3's full stage-then-verify-then-commit sequence in one place deliberately
	isPG := isPostgresStorage(cfg)

	dbPath := cfg.Storage.Database.Path
	if dbPath == "" {
		dbPath = "./secrets.db"
	}
	if isPG {
		if err := refuseNonEmptyPostgresTarget(cfg); err != nil {
			return err
		}
	} else if err := refuseNonEmptyExisting("database", dbPath); err != nil {
		return err
	}
	targetKeyPaths, err := expectedKeyFilePaths(cfg)
	if err != nil {
		return err
	}
	for _, p := range targetKeyPaths {
		if err := refuseNonEmptyExisting("key file", p); err != nil {
			return err
		}
	}
	if err := refuseExistingKeySetManifest(cfg); err != nil {
		return err
	}

	archiveInfo, err := os.Stat(restoreInput)
	if err != nil {
		return fmt.Errorf("stat %q: %w", restoreInput, err)
	}
	// Staging needs roughly the uncompressed archive size again on top of
	// what's already on disk (the compressed archive itself); 4x the
	// compressed size is a deliberately generous, simple estimate (design
	// §7.4 doesn't mandate a precise compression-ratio calculation).
	if err := backupfmt.CheckFreeSpace(restoreInput, saturatingQuadruple(archiveInfo.Size())); err != nil {
		return fmt.Errorf("preflight free-space check (design §7.4): %w", err)
	}

	stagingDir, err := os.MkdirTemp("", "keyorix-admin-restore-*")
	if err != nil {
		return fmt.Errorf("create staging directory: %w", err)
	}
	defer os.RemoveAll(stagingDir) //nolint:errcheck

	archiveFile, err := secretenv.OpenRegularNamed("backup archive", restoreInput) // operator-supplied input path; a FIFO is refused, not waited on
	if err != nil {
		return fmt.Errorf("open %q: %w", restoreInput, err)
	}
	manifest, err := backupfmt.ExtractArchive(archiveFile, stagingDir, restoreMaxEntryBytes, restoreMaxTotalBytes)
	_ = archiveFile.Close()
	if err != nil {
		return fmt.Errorf("extract backup archive %q: %w", restoreInput, err)
	}

	if manifest.Backend != backupfmt.Backend {
		return fmt.Errorf("backup archive is format %q, this binary writes/expects %q -- restore refuses to mix formats",
			manifest.Backend, backupfmt.Backend)
	}
	if storage.SchemaEpochTooNew(manifest.SchemaEpoch) {
		return fmt.Errorf("backup archive's schema epoch %d is newer than this binary's schema epoch %d (ADR-097) -- "+
			"this backup was taken by a newer version of Keyorix; upgrade this binary before restoring it",
			manifest.SchemaEpoch, storage.CurrentSchemaEpoch())
	}
	if err := validateKeyFileSetV2(manifest.KeyFiles, targetKeyPaths); err != nil {
		return err
	}

	// design §5.3 step 2: unwrap the KEK from the archive's own STAGED
	// (still-wrapped) key files -- never the real target's, which has none
	// yet on a fresh restore. kekStagingDir is laid out with the SAME
	// relative paths cfg.Storage.Encryption expects, so the exact same
	// internal/encryption code path `admin diagnose`/`admin backup` use
	// works unmodified, just pointed elsewhere.
	stagedCfg, kekStagingDir, err := stageKeyFilesForKEKUnwrap(cfg, stagingDir, manifest.KeyFiles, targetKeyPaths)
	if err != nil {
		return err
	}
	manifestKey, err := unwrapManifestKeyWith(stagedCfg, kekStagingDir, restorePassphrase.resolve, nil)
	if err != nil {
		return err
	}
	defer crypto.WipeBytes(manifestKey)

	if !backupfmt.VerifyManifestSignature(manifest, manifestKey) {
		return fmt.Errorf("backup archive's manifest signature is invalid -- the archive may be corrupted or " +
			"tampered with; restore refuses")
	}

	// Rollback protection (§6.3) -- BEFORE any write to the real target,
	// reusing checkRollbackProtection UNCHANGED (the same function #2233
	// added and this restore path's v1 sibling still uses) by re-encoding
	// the v2 manifest's structured Checkpoint back into the same encoded
	// string shape ParseHighWater already knows. On Postgres, dbPath is
	// replaced by a synthesized identity path (postgresTargetIdentityPath)
	// used ONLY for its directory component (auditverify.WitnessPath) --
	// there is no single database file to open directly, so every count
	// below is read via the Postgres-specific helpers instead.
	identityPath := dbPath
	var destinationFloor, newerSubstantive int64
	highWaterEncoded := checkpointBundleToHighWaterString(manifest.Checkpoint)
	archiveRaw, err := archiveHeadFromStagedAuditEvents(stagingDir, manifest)
	if err != nil {
		return fmt.Errorf("read the archived database's audit event count: %w", err)
	}
	if isPG {
		identityPath, err = postgresTargetIdentityPath(cfg)
		if err != nil {
			return err
		}
		destinationFloor, err = postgresAuditEventCount(cfg)
		if err != nil {
			return fmt.Errorf("read existing destination database's audit event count: %w", err)
		}
		newerSubstantive, err = postgresAuditEventsNewerThan(cfg, archiveRaw)
		if err != nil {
			return fmt.Errorf("read existing destination database's newer audit events: %w", err)
		}
	} else {
		destinationFloor, err = readExistingDatabaseAuditEventCount(dbPath)
		if err != nil {
			return fmt.Errorf("read existing destination database's audit event count: %w", err)
		}
		newerSubstantive, err = destinationEventsNewerThan(dbPath, archiveRaw)
		if err != nil {
			return fmt.Errorf("read existing destination database's newer audit events: %w", err)
		}
	}
	rollbackCheck, err := checkRollbackProtection(highWaterEncoded, identityPath, destinationFloor, archiveRaw, newerSubstantive)
	if err != nil {
		return err
	}

	// Only past every check above: stage the key files, load the data, and
	// install both only once the load has committed (restore_commit.go).
	restoreTS := time.Now().UTC().Format("20060102T150405Z")
	keyFileData := make([][]byte, len(manifest.KeyFiles))
	for i, entry := range manifest.KeyFiles {
		data, rerr := os.ReadFile(filepath.Join(stagingDir, entry.TarName)) // #nosec G304 -- our own staged file, already checksum-verified by ExtractArchive
		if rerr != nil {
			return fmt.Errorf("read staged key file %q: %w", entry.TarName, rerr)
		}
		keyFileData[i] = data
	}
	journalPath, err := restorejournal.Path(cfg)
	if err != nil {
		return err
	}
	if journalPath == "" {
		return fmt.Errorf("internal error: no restore journal location for this config")
	}
	// One set, staged before anything is installed: these key files form one
	// encryption configuration's required set (keyfiles.Registry), and a host
	// with only SOME of them present can never start. The key-set manifest
	// recording them is staged as part of the same set.
	entries, err := prepareRestoredKeySet(cfg, targetKeyPaths, keyFileData)
	if err != nil {
		return fmt.Errorf("stage key file set: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			discardStagedEntries(entries)
		}
	}()
	if err := restoreStepHook("staged"); err != nil {
		return err
	}
	journal := restorejournal.Journal{
		Backend:   "sqlite",
		Timestamp: restoreTS,
		Overwrite: restoreOverwriteExisting,
		CompletedEvent: fmt.Sprintf("restored from backup archive %s (created %s, format v2)",
			restoreInput, manifest.CreatedAt.Format(time.RFC3339)),
	}
	if rollbackCheck.archiveEncoded != "" {
		witnessPath, werr := filepath.Abs(auditverify.WitnessPath(identityPath))
		if werr != nil {
			return fmt.Errorf("resolve the rollback-protection witness path: %w", werr)
		}
		journal.WitnessPath, journal.WitnessValue = witnessPath, rollbackCheck.archiveEncoded
	}
	if rollbackCheck.overrodeRollback {
		journal.RollbackOverrideEvent = fmt.Sprintf("restored a backup that is %d audit event(s) behind this host's last known state "+
			"(--allow-rollback was used) -- any user/credential revocation recorded after that point is undone by this restore",
			rollbackCheck.gapEvents)
	}

	if isPG {
		journal.Backend = "postgres"
		if journal.Token, err = newRestoreToken(); err != nil {
			return err
		}
		journal.Entries = entries
		if err := restorejournal.Write(journalPath, journal); err != nil {
			return err
		}
		if committed, err = loadPostgresRestore(cfg, manifest, stagingDir, journal.Token); err != nil {
			if !committed {
				if rerr := restorejournal.Remove(journalPath); rerr != nil {
					return fmt.Errorf("%w (and removing the restore journal failed: %v -- run `keyorix-server admin restore --recover`)", err, rerr)
				}
			}
			return err
		}
	} else {
		absDB, aerr := filepath.Abs(dbPath)
		if aerr != nil {
			return fmt.Errorf("resolve %q: %w", dbPath, aerr)
		}
		stagedDB := fmt.Sprintf("%s.restoring-%s", absDB, restoreTS)
		entries = append(entries, restorejournal.Entry{Path: absDB, Staged: stagedDB, SQLiteDB: true})
		if err := buildStagedSQLiteRestore(cfg, stagedDB, manifest, stagingDir); err != nil {
			return err
		}
		if entries[len(entries)-1].SHA256, err = restorejournal.HashFile(stagedDB); err != nil {
			return fmt.Errorf("hash staged database: %w", err)
		}
		if err := restoreStepHook("loaded"); err != nil {
			return err
		}
		journal.Entries = entries
		if err := restorejournal.Write(journalPath, journal); err != nil {
			return err
		}
		committed = true
		if err := restoreStepHook("journal-written"); err != nil {
			return err
		}
	}

	if err := installJournalEntries(journalPath, &journal); err != nil {
		return restoreInterruptedError(journalPath, err)
	}

	var totalRows int64
	for _, te := range manifest.Tables {
		totalRows += te.RowCount
	}
	fmt.Printf("Restored %d table(s), %d row(s), %d key file(s) from %s (backup created %s)\n",
		len(manifest.Tables), totalRows, len(manifest.KeyFiles), restoreInput, manifest.CreatedAt.Format(time.RFC3339))
	if restoreOverwriteExisting {
		fmt.Printf("The replaced key files and database were kept as <path>.pre-restore-%s.\n", restoreTS)
	}
	fmt.Println("Run 'keyorix-server admin diagnose' to further confirm the restore.")

	if err := finishRestore(cfg, journalPath, journal); err != nil {
		return err
	}
	if isPG {
		return verifyRestoredAuditPostgres(cfg)
	}
	return verifyRestoredAudit(cfg, dbPath)
}

// loadPostgresRestore is the PostgreSQL commit point: migrations, then ONE
// transaction that clears the target (--overwrite-existing), loads the
// archive, resyncs sequences and writes token. committed reports whether that
// transaction committed; when its COMMIT fails ambiguously the token is read
// back, and an unreadable outcome keeps the journal (committed stays true so
// the caller does not discard what --recover may still need).
func loadPostgresRestore(cfg *config.Config, manifest backupfmt.Manifest, stagingDir, token string) (committed bool, err error) {
	if err := restoreStepHook("journal-written"); err != nil {
		return false, err
	}
	fmt.Println("Running migrations against the target database...")
	if _, err := storage.NewStorageFactory().CreateStorage(cfg); err != nil {
		return false, fmt.Errorf("migrate restored database: %w", err)
	}
	targetDB, err := storage.OpenGormDB(cfg)
	if err != nil {
		return false, fmt.Errorf("open freshly-migrated target database: %w", err)
	}
	defer closeGormDB(targetDB)

	fmt.Println("Loading data into the restored database in one transaction...")
	loadErr := targetDB.Transaction(func(tx *gorm.DB) error {
		if restoreOverwriteExisting {
			if err := clearPostgresRestoreTarget(tx); err != nil {
				return err
			}
		}
		if err := backupfmt.LoadArchive(tx, manifest, stagingDir); err != nil {
			return err
		}
		if err := backfillOTPExpiryForOlderArchive(tx, manifest); err != nil {
			return err
		}
		// Every restored row carries its original, explicit id; PostgreSQL
		// never advances a sequence for an explicit-value INSERT. See
		// resyncPostgresSequences.
		if err := resyncPostgresSequences(tx); err != nil {
			return fmt.Errorf("resync Postgres sequences after restore: %w", err)
		}
		if err := writePostgresRestoreToken(tx, token); err != nil {
			return fmt.Errorf("record the restore's commit token: %w", err)
		}
		return restoreStepHook("loaded")
	})
	if loadErr == nil {
		return true, restoreStepHook("committed")
	}
	done, qerr := postgresRestoreTokenCommitted(cfg, token)
	if qerr != nil {
		return true, fmt.Errorf("load backup data: %w -- and whether it committed cannot be read back (%v); the "+
			"restore journal is kept: run `keyorix-server admin restore --recover`", loadErr, qerr)
	}
	if done {
		return true, nil // the COMMIT reached the database; carry on installing the key files
	}
	return false, fmt.Errorf("load backup data: %w -- nothing was changed: the transaction rolled back and the "+
		"live key files were never touched", loadErr)
}

// buildStagedSQLiteRestore creates, migrates and loads the restored database
// at stagedDB (next to the live one, which stays untouched), then closes it
// and folds any WAL into the file so a single rename can install it.
func buildStagedSQLiteRestore(cfg *config.Config, stagedDB string, manifest backupfmt.Manifest, stagingDir string) (err error) {
	defer func() {
		if err != nil {
			_ = os.Remove(stagedDB)
			_ = removeStagedSQLiteSidecars(stagedDB)
		}
	}()
	stagedCfg := *cfg
	stagedCfg.Storage.Database.Path = stagedDB
	fmt.Println("Running migrations against a fresh staged database...")
	st, err := storage.NewStorageFactory().CreateStorage(&stagedCfg)
	if err != nil {
		return fmt.Errorf("migrate restored database: %w", err)
	}
	if c, ok := st.(interface{ Close() error }); ok {
		_ = c.Close()
	}
	targetDB, err := storage.OpenGormDB(&stagedCfg)
	if err != nil {
		return fmt.Errorf("open freshly-migrated staged database: %w", err)
	}
	fmt.Println("Loading data into the staged database...")
	loadErr := targetDB.Transaction(func(tx *gorm.DB) error {
		if err := backupfmt.LoadArchive(tx, manifest, stagingDir); err != nil {
			return err
		}
		return backfillOTPExpiryForOlderArchive(tx, manifest)
	})
	if loadErr == nil {
		loadErr = targetDB.Exec("PRAGMA wal_checkpoint(TRUNCATE)").Error
	}
	closeGormDB(targetDB)
	if loadErr != nil {
		return fmt.Errorf("load backup data: %w -- nothing was changed: the live database and key files were never touched", loadErr)
	}
	if info, serr := os.Stat(stagedDB + "-wal"); serr == nil && info.Size() > 0 {
		return fmt.Errorf("staged database %q still has a non-empty WAL after closing -- refusing to install it", stagedDB)
	}
	if err := removeStagedSQLiteSidecars(stagedDB); err != nil {
		return err
	}
	f, err := os.Open(stagedDB) // #nosec G304 -- dbPath-derived staging name
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck
	return f.Sync()
}

// validateKeyFileSetV2 is validateKeyFileSetV1 (backup_v1_legacy.go) for
// backupfmt.KeyFileEntry.
func validateKeyFileSetV2(archived []backupfmt.KeyFileEntry, target []string) error {
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

// stageKeyFilesForKEKUnwrap copies each archive key file's ALREADY-STAGED,
// checksum-verified bytes (in stagingDir/<TarName>, per ExtractArchive) into
// a fresh subdirectory mirroring the paths cfg.Storage.Encryption expects,
// and returns a copy of cfg whose key paths point at that mirror -- so
// unwrapManifestKey can point a real encryption.Service at it unmodified.
//
// #2604: every staged path must land INSIDE the staging directory. A
// relative key path already did; an ABSOLUTE one (the Docker image's
// /app/keys/... config) used to resolve, via keyfiles.Registry, to the real
// target path itself, so this "staging" step wrote the archive's key files
// straight into the target's key directory -- and commitRestoredFile's
// concurrent-creation guard then (correctly) refused to overwrite them,
// failing every restore onto a fresh, empty keys volume. stagedKeyPath/
// stagedEncryptionConfig (backup.go) re-root absolute paths under the
// staging directory instead; the guard itself is unchanged.
//
// targetKeyPaths is expectedKeyFilePaths(cfg), already validated 1:1 against
// keyFileEntries by validateKeyFileSetV2. Destinations are derived from it
// (config), never from the archive's own key-file metadata.
func stageKeyFilesForKEKUnwrap(cfg *config.Config, stagingDir string, keyFileEntries []backupfmt.KeyFileEntry, targetKeyPaths []string) (*config.Config, string, error) {
	kekDir := filepath.Join(stagingDir, "kek-material")
	if err := os.MkdirAll(kekDir, 0700); err != nil {
		return nil, "", fmt.Errorf("create KEK-unwrap staging directory: %w", err)
	}
	if len(targetKeyPaths) != len(keyFileEntries) {
		return nil, "", fmt.Errorf("internal error: %d expected key-file paths but %d archive key files", len(targetKeyPaths), len(keyFileEntries))
	}
	for i, entry := range keyFileEntries {
		data, err := os.ReadFile(filepath.Join(stagingDir, entry.TarName)) // #nosec G304 -- our own staged file, already checksum-verified by ExtractArchive
		if err != nil {
			return nil, "", fmt.Errorf("read staged key file %q: %w", entry.TarName, err)
		}
		// dest is computed from targetKeyPaths[i] (cfg.Storage.Encryption via
		// keyfiles.Registry) and kekDir only -- never from entry, the
		// archive-controlled metadata data was read from above. gosec's taint
		// analysis (G703) flags this write because data and dest both trace
		// back through the same loop iteration, but only the ARRAY INDEX
		// correlates with entry, not the path value.
		dest := stagedKeyPath(kekDir, targetKeyPaths[i])
		if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			return nil, "", fmt.Errorf("create directory for staged key file %q: %w", dest, err)
		}
		if err := os.WriteFile(dest, data, 0600); err != nil { // #nosec G703 -- dest is config-derived (see above), not archive-controlled
			return nil, "", fmt.Errorf("stage key file at %q: %w", dest, err)
		}
	}
	stagedCfg := *cfg
	stagedCfg.Storage.Encryption = stagedEncryptionConfig(cfg.Storage.Encryption, kekDir)
	return &stagedCfg, kekDir, nil
}

// checkpointBundleToHighWaterString converts a v2 manifest's structured
// Checkpoint (design §5.4's ExternalAnchorBundle shape) back into the exact
// encoded string shape auditverify.ParseHighWater/EncodeHighWater use --
// letting checkRollbackProtection stay completely unchanged (and therefore
// exactly as tested) across both the v1 and v2 restore paths. nil (no
// checkpoint recorded -- a fresh/young source install) encodes to "".
func checkpointBundleToHighWaterString(b *auditverify.ExternalAnchorBundle) string {
	if b == nil {
		return ""
	}
	cp := &auditverify.Checkpoint{
		ChainedEvents: b.ChainedEvents,
		HeadID:        b.HeadID,
		HeadHash:      b.HeadHash,
		KeyVersion:    b.KeyVersion,
	}
	return auditverify.EncodeHighWater(cp, b.Signature)
}

// archiveHeadFromStagedAuditEvents returns the archived database's raw
// MAX(audit_events.id) -- the v2 equivalent of v1's
// auditEventCountFromDBBytes, computed by scanning the staged
// audit_events.ndjson file (rows are written in primary-key-ascending
// order, design §3.3, so the LAST successfully-parsed row's ID is the
// max) instead of querying a single-file SQLite image, since v2 has no
// such single file. 0 if the archive has no audit_events table entry at
// all (an install that never logged an event).
func archiveHeadFromStagedAuditEvents(stagingDir string, manifest backupfmt.Manifest) (int64, error) {
	var tarName string
	for _, te := range manifest.Tables {
		if te.Name == "audit_events" {
			tarName = te.TarName
			break
		}
	}
	if tarName == "" {
		return 0, nil
	}
	f, err := os.Open(filepath.Join(stagingDir, tarName)) // #nosec G304 -- our own staged file, already checksum-verified by ExtractArchive
	if err != nil {
		return 0, fmt.Errorf("open staged audit_events file: %w", err)
	}
	defer f.Close() //nolint:errcheck

	var maxID int64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<30)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var row struct {
			ID uint
		}
		if err := json.Unmarshal(line, &row); err != nil {
			return 0, fmt.Errorf("decode staged audit_events row: %w", err)
		}
		// #nosec G115 -- row.ID is an audit_events auto-increment primary key;
		// reaching math.MaxInt64 would require over 9.2 quintillion rows, not
		// a realistic overflow surface (the same reasoning this codebase's
		// preflight.go already applies to a filesystem block count/size
		// conversion).
		if int64(row.ID) > maxID {
			maxID = int64(row.ID)
		}
	}
	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("read staged audit_events file: %w", err)
	}
	return maxID, nil
}

// runAdminRestoreV1 restores an archive written by the pre-2026-09-28
// physical (SQLite-only) format (#2099) -- unchanged from that format's
// original restore logic, kept until Keyorix 1.0 (design §3.6 decision 3).
func runAdminRestoreV1(cfg *config.Config) error {
	// v1 archives are always physical SQLite-file copies (#2099 never
	// supported any other backend) -- refuse a Postgres TARGET explicitly
	// here, rather than relying on manifest.Backend != "sqlite" below, which
	// only checks the ARCHIVE's own (always "sqlite") declared backend and
	// would otherwise silently pass regardless of cfg.Storage.Type, now that
	// runAdminRestore's outer gate admits Postgres configs too (H4).
	if isPostgresStorage(cfg) {
		return fmt.Errorf("this archive uses the deprecated v1 (physical, SQLite-only) backup format, which never " +
			"supported a Postgres target -- restore it into a SQLite-backed config, or take a fresh v2 backup")
	}
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
	if err := validateKeyFileSetV1(manifest.KeyFiles, targetKeyPaths); err != nil {
		return err
	}

	if err := verifyChecksumV1(manifest.DBFile, dbBytes); err != nil {
		return err
	}
	for i, entry := range manifest.KeyFiles {
		if err := verifyChecksumV1(entry, keyBlobs[i]); err != nil {
			return err
		}
		if err := refuseNonEmptyExisting("key file", entry.OriginalPath); err != nil {
			return err
		}
	}
	if err := refuseExistingKeySetManifest(cfg); err != nil {
		return err
	}

	destinationFloor, err := readExistingDatabaseAuditEventCount(dbPath)
	if err != nil {
		return fmt.Errorf("read existing destination database's audit event count: %w", err)
	}
	archiveRaw, err := auditEventCountFromDBBytes(dbBytes)
	if err != nil {
		return fmt.Errorf("read the archived database's audit event count: %w", err)
	}
	newerSubstantive, err := destinationEventsNewerThan(dbPath, archiveRaw)
	if err != nil {
		return fmt.Errorf("read existing destination database's newer audit events: %w", err)
	}
	rollbackCheck, err := checkRollbackProtection(manifest.AuditHighWater, dbPath, destinationFloor, archiveRaw, newerSubstantive)
	if err != nil {
		return err
	}

	restoreTS := time.Now().UTC().Format("20060102T150405Z")

	// Keys and database staged first, then installed together under a
	// journal (restore_commit.go): a crash in between is rolled forward by
	// --recover instead of leaving new keys beside the old database.
	keyFilePaths := make([]string, len(manifest.KeyFiles))
	for i, entry := range manifest.KeyFiles {
		keyFilePaths[i] = entry.OriginalPath
	}
	journalPath, err := restorejournal.Path(cfg)
	if err != nil {
		return err
	}
	entries, err := prepareRestoredKeySet(cfg, keyFilePaths, keyBlobs)
	if err != nil {
		return fmt.Errorf("stage restored files: %w", err)
	}
	dbEntry, err := prepareRestoredFileSet([]string{dbPath}, [][]byte{dbBytes})
	if err != nil {
		discardStagedEntries(entries)
		return fmt.Errorf("stage restored files: %w", err)
	}
	dbEntry[0].SQLiteDB = true
	entries = append(entries, dbEntry[0])
	journal := restorejournal.Journal{Backend: "sqlite", Timestamp: restoreTS, Overwrite: restoreOverwriteExisting, Entries: entries,
		CompletedEvent: fmt.Sprintf("restored from backup archive %s (created %s, format v1)", restoreInput, manifest.CreatedAt.Format(time.RFC3339))}
	if err := restorejournal.Write(journalPath, journal); err != nil {
		discardStagedEntries(entries)
		return err
	}
	if err := installJournalEntries(journalPath, &journal); err != nil {
		return restoreInterruptedError(journalPath, err)
	}
	if err := restorejournal.Remove(journalPath); err != nil {
		return err
	}

	fmt.Println("Applying pending migrations to the restored database (idempotent)...")
	if _, err := storage.NewStorageFactory().CreateStorage(cfg); err != nil {
		return fmt.Errorf("migrate restored database: %w", err)
	}

	fmt.Printf("Restored database (%d bytes) and %d key file(s) from %s (backup created %s)\n",
		len(dbBytes), len(manifest.KeyFiles), restoreInput, manifest.CreatedAt.Format(time.RFC3339))
	fmt.Println("Run 'keyorix-server admin diagnose' to further confirm the restore.")

	recordAdminAction(cfg, "admin.restore_completed",
		fmt.Sprintf("restored from backup archive %s (created %s, format v1)", restoreInput, manifest.CreatedAt.Format(time.RFC3339)), true)

	if rollbackCheck.archiveEncoded != "" {
		if _, werr := auditverify.WriteWitnessIfHigher(auditverify.WitnessPath(dbPath), rollbackCheck.archiveEncoded); werr != nil {
			fmt.Printf("note: could not update the rollback-protection witness file: %v\n", werr)
		}
	}
	if rollbackCheck.overrodeRollback {
		recordAdminAction(cfg, "admin.restore_rollback_override",
			fmt.Sprintf("restored a backup that is %d audit event(s) behind this host's last known state "+
				"(--allow-rollback was used) -- any user/credential revocation recorded after that point is undone by this restore",
				rollbackCheck.gapEvents), true)
	}

	return verifyRestoredAudit(cfg, dbPath)
}

// rollbackCheckOutcome is checkRollbackProtection's result: whether the
// restore was allowed to proceed past a detected rollback, the size of that
// gap (for the audit event runAdminRestoreV1/V2 write once the restored
// chain is writable again), and the archive's own raw encoded high-water
// value (so the caller can advance the witness file to it after a
// successful restore, without re-parsing the manifest).
type rollbackCheckOutcome struct {
	overrodeRollback bool
	gapEvents        int64
	archiveEncoded   string
}

// checkRollbackProtection implements design-b3-backup-v2.md §6.3: compares
// the archive's own certified audit-trail progress (highWaterEncoded, empty
// if the source install had never written a checkpoint) against this host's
// witness file (sibling to dbPath, maintained by every server this host has
// run) BEFORE the caller writes anything to disk. Returns an error
// (refusing the restore) if the archive is behind and --allow-rollback was
// not given; any note worth printing is returned alongside a nil error
// otherwise. Shared unchanged by both the v1 and v2 restore paths --
// checkpointBundleToHighWaterString adapts v2's structured Checkpoint into
// this same encoded-string contract rather than this function changing.
//
// Reference = max(witness file, destinationFloor) -- destinationFloor (see
// readExistingDatabaseAuditEventCount) is the CURRENT destination database's
// own live raw audit-event count, read moments ago, right before this
// restore would overwrite it (0 when there is no pre-existing destination
// database). The witness file alone only advances on a checkpoint
// (scheduled, default every 24h, or on-demand) or a prior restore -- a
// change made to the destination since the last checkpoint would not have
// touched the witness at all. destinationFloor closes that gap: it has no
// checkpoint delay, because it is read directly, right now, from the exact
// database this restore is about to destroy.
//
// Three cases, per §6.3 (reference substituted for "witness" throughout):
//   - reference is 0 (no witness AND no pre-existing destination database):
//     nothing to compare against (a genuinely fresh host, or the first
//     restore ever run on this one) -- proceed. This is the legitimate
//     bootstrap case, not a gap to close.
//   - archive's high-water >= reference: this backup is at least as current
//     as anything this host has certified or the destination itself
//     contains -- proceed normally.
//   - archive's high-water < reference: refuse unless --allow-rollback.
//
// A malformed manifest.AuditHighWater (non-empty but unparseable -- a
// tampered or corrupted manifest) and a malformed witness file (exists but
// unparseable) are BOTH treated as hard errors, never silently downgraded to
// "absent" -- deleting or corrupting either one must not be a way to evade
// this check.
func checkRollbackProtection(highWaterEncoded, dbPath string, destinationFloor, archiveRaw, newerSubstantive int64) (rollbackCheckOutcome, error) {
	var archiveSigned int64
	archiveCP := &auditverify.Checkpoint{}
	if highWaterEncoded != "" {
		var ok bool
		archiveCP, _, ok = auditverify.ParseHighWater(highWaterEncoded)
		if !ok {
			return rollbackCheckOutcome{}, fmt.Errorf(
				"backup archive's manifest carries an audit high-water value that does not parse -- " +
					"the manifest may be corrupted or tampered with; restore refuses rather than treat this as if the archive had no recorded history")
		}
		archiveSigned = archiveCP.ChainedEvents
	}

	witnessPath := auditverify.WitnessPath(dbPath)
	witnessCP, _, found, err := auditverify.ReadWitness(witnessPath)
	if err != nil {
		return rollbackCheckOutcome{}, fmt.Errorf(
			"could not read the rollback-protection witness file %q: %w -- investigate before proceeding "+
				"(a corrupted witness is not treated as absent)", witnessPath, err)
	}

	// Two independent comparisons, each between values of the same kind:
	//   - raw: the live destination database's MAX(audit_events.id) vs the
	//     archived database's own MAX(audit_events.id);
	//   - signed: the host witness's certified high-water vs the archive's
	//     certified high-water.
	// The archive is behind if EITHER says so; the reported gap is the larger.
	var gap, archiveEvents, reference int64
	// Raw: only events newer than the archive's own head that are NOT the
	// backup tool's own bookkeeping count (admin backup writes
	// admin.backup_created AFTER taking its snapshot, so the source database
	// is always one bookkeeping event ahead of its own freshest backup).
	if newerSubstantive > 0 {
		gap, archiveEvents, reference = newerSubstantive, archiveRaw, destinationFloor
	}
	// Sealed marks (admin audit accept-loss): a mark written under more seals
	// is newer whatever its count, because an accepted loss lowers the count.
	// An archive from before a seal this host accepted is behind (it would
	// bring back the state the seal replaced); one from after a seal the
	// witness has not seen is not.
	switch {
	case found && witnessCP.Seals > archiveCP.Seals:
		if !restoreAllowRollback {
			return rollbackCheckOutcome{}, fmt.Errorf(
				"refusing to restore: this backup was taken before audit loss acceptance #%d recorded on this host "+
					"(the archive's audit trail is under %d seal(s), this host's under %d) -- restoring it would bring back the "+
					"state that acceptance replaced and un-revoke access revoked since. Pass --allow-rollback if this is a "+
					"genuine disaster-recovery restore of an intentionally older backup", archiveCP.Seals+1, archiveCP.Seals, witnessCP.Seals)
		}
		fmt.Printf("WARNING: --allow-rollback is in effect. This backup was taken before audit loss acceptance #%d recorded "+
			"on this host. Recording this override to the audit trail.\n", archiveCP.Seals+1)
		return rollbackCheckOutcome{overrodeRollback: true, gapEvents: max(gap, 1), archiveEncoded: highWaterEncoded}, nil
	case found && witnessCP.Seals < archiveCP.Seals:
		// The archive is newer by seal order; only the raw comparison applies.
	case found && witnessCP.ChainedEvents > archiveSigned && witnessCP.ChainedEvents-archiveSigned > gap:
		gap, archiveEvents, reference = witnessCP.ChainedEvents-archiveSigned, archiveSigned, witnessCP.ChainedEvents
	}
	if gap == 0 {
		return rollbackCheckOutcome{archiveEncoded: highWaterEncoded}, nil
	}
	if !restoreAllowRollback {
		return rollbackCheckOutcome{}, fmt.Errorf(
			"refusing to restore: this backup's audit trail (%d event(s)) is %d event(s) BEHIND this host's own "+
				"last known state (%d event(s)) -- restoring it would silently un-revoke any user/credential access "+
				"revoked since this backup was taken. Pass --allow-rollback if this is a genuine disaster-recovery "+
				"restore of an intentionally older backup", archiveEvents, gap, reference)
	}
	fmt.Printf("WARNING: --allow-rollback is in effect. This backup's audit trail (%d event(s)) is %d event(s) "+
		"behind this host's own last known state (%d event(s)) -- proceeding will silently un-revoke any "+
		"user/credential access revoked since this backup was taken. Recording this override to the audit trail.\n",
		archiveEvents, gap, reference)
	return rollbackCheckOutcome{overrodeRollback: true, gapEvents: gap, archiveEncoded: highWaterEncoded}, nil
}

// readExistingDatabaseAuditEventCount opens dbPath (a SQLite file that may
// or may not exist yet) read-only and returns the raw, live MAX(id) from its
// audit_events table -- 0 when the file does not exist, is empty, or the
// table itself does not exist yet (a genuinely fresh/pre-migration database,
// not an error). This is deliberately a raw, unsigned count, not the signed
// checkpoint high-water: it needs to reflect changes made moments ago, with
// no checkpoint-interval delay, since it is read immediately before this
// exact database would be overwritten.
// rollbackBookkeepingEventTypes are audit events the admin tool itself writes
// around a backup; they never represent a revocation or any access change,
// so they do not make a destination "newer" than an archive.
var rollbackBookkeepingEventTypes = []string{"admin.backup_created"}

// destinationEventsNewerThan counts audit events in the existing destination
// database with id > archiveHead, excluding rollbackBookkeepingEventTypes.
// 0 when there is no destination database or no audit_events table.
func destinationEventsNewerThan(dbPath string, archiveHead int64) (int64, error) {
	info, statErr := os.Stat(dbPath)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return 0, nil
		}
		return 0, fmt.Errorf("stat %q: %w", dbPath, statErr)
	}
	if info.Size() == 0 {
		return 0, nil
	}
	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		return 0, fmt.Errorf("open %q read-only: %w", dbPath, err)
	}
	defer db.Close() //nolint:errcheck
	var n int64
	q := "SELECT COUNT(*) FROM audit_events WHERE id > ? AND event_type NOT IN (" +
		strings.TrimSuffix(strings.Repeat("?,", len(rollbackBookkeepingEventTypes)), ",") + ")"
	args := []any{archiveHead}
	for _, et := range rollbackBookkeepingEventTypes {
		args = append(args, et)
	}
	if err := db.QueryRow(q, args...).Scan(&n); err != nil { // nosemgrep: go.lang.security.audit.sqli.gosql-sqli.gosql-sqli -- q's dynamic part is only a "?,?,..." placeholder run sized off len(rollbackBookkeepingEventTypes) (a package-level literal slice); every actual value (archiveHead, et) is passed as a parameterized arg, never interpolated into q
		if strings.Contains(err.Error(), "no such table") {
			return 0, nil
		}
		return 0, fmt.Errorf("count newer audit events in %q: %w", dbPath, err)
	}
	return n, nil
}

func readExistingDatabaseAuditEventCount(dbPath string) (int64, error) {
	info, statErr := os.Stat(dbPath)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return 0, nil
		}
		return 0, fmt.Errorf("stat %q: %w", dbPath, statErr)
	}
	if info.Size() == 0 {
		return 0, nil
	}

	db, err := sql.Open("sqlite", "file:"+dbPath+"?mode=ro")
	if err != nil {
		return 0, fmt.Errorf("open %q read-only: %w", dbPath, err)
	}
	defer db.Close() //nolint:errcheck

	var count sql.NullInt64
	if err := db.QueryRow("SELECT MAX(id) FROM audit_events").Scan(&count); err != nil {
		// A missing audit_events table (a database created but never
		// migrated) is the fresh-database case, not a hard error -- every
		// other error (a genuinely corrupt or unreadable file) is.
		if strings.Contains(err.Error(), "no such table") {
			return 0, nil
		}
		return 0, fmt.Errorf("read audit_events count from %q: %w", dbPath, err)
	}
	return count.Int64, nil
}

// verifyRestoredAudit runs the same offline audit-chain re-walk
// `admin verify-audit` exposes as a standalone command, directly against the
// just-restored database file -- never through the config's normal
// server-guard-locked path, since this restore already holds that lock for
// its own duration (see acquireDatabaseLock above; a second acquisition
// attempt on the same config would just fail).
//
// A checksum (v1) or a manifest signature (v2) only prove the archive was
// not corrupted/tampered IN TRANSIT -- this is the step in restore that can
// detect the RESTORED DATABASE was tampered with (or the source itself was,
// before backup ever ran), by re-walking its ADR-029 audit hash chain -- run
// automatically so an operator doesn't have to remember to do it by hand.
// Only a BROKEN verdict fails restore (non-zero exit); VALID and
// INDETERMINATE are both reported but do not, matching verify-audit's own
// documented semantics.
func verifyRestoredAudit(cfg *config.Config, dbPath string) error {
	db, err := auditverify.OpenSQLiteReadOnly(dbPath)
	if err != nil {
		return fmt.Errorf("open restored database for automatic verify-audit: %w", err)
	}
	defer db.Close() //nolint:errcheck
	return runVerifyRestoredAudit(cfg, db)
}

// runVerifyRestoredAudit is verifyRestoredAudit's backend-neutral core,
// shared with verifyRestoredAuditPostgres (restore_postgres.go) -- takes an
// already-opened auditverify.DB (either dialect; that package's own
// independence requirement means every query past this point is identical
// regardless of which one it is).
func runVerifyRestoredAudit(cfg *config.Config, db *auditverify.DB) error {
	var opts auditverify.Options
	if cfg.Audit.OfflineAnchorPath != "" {
		data, err := secretenv.ReadRegularFile("audit anchor", cfg.Audit.OfflineAnchorPath) // operator-configured path (audit.offline_anchor_path); a FIFO is refused, not waited on
		if err != nil {
			return fmt.Errorf("automatic verify-audit: read configured offline anchor %q: %w", cfg.Audit.OfflineAnchorPath, err)
		}
		bundle, err := auditverify.ParseExternalAnchorBundle(data)
		if err != nil {
			return fmt.Errorf("automatic verify-audit: parse configured offline anchor %q: %w", cfg.Audit.OfflineAnchorPath, err)
		}
		opts.ExternalAnchor = bundle
	}

	// The restored key files are in place by now: derive the same KEK-derived
	// checkpoint key `admin audit export-checkpoint-key` would write, so a retention
	// gap left by a sanctioned purge authenticates (without it every database that was
	// ever purged restored as INDETERMINATE, while `admin verify-audit
	// --checkpoint-key-file` on the same data said VALID). A failure to derive it is
	// not fatal: verification still runs, and says why it could not authenticate.
	if key, _, kerr := deriveCheckpointKeyWith(cfg, restorePassphrase.resolve); kerr == nil {
		defer crypto.WipeBytes(key)
		opts.CheckpointKey = key
	} else {
		fmt.Printf("note: could not derive the audit-checkpoint key for the automatic verify-audit: %v\n", kerr)
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

// removeStaleSQLiteSidecars removes dbPath's WAL-mode sidecar files
// (-wal, -shm) if present. Best-effort existence-based removal: absent is
// the common/expected case (a genuinely fresh data dir), not an error.
// removeStagedSQLiteSidecars removes a staged (never live) database's
// sidecars: -wal/-shm and the migration lock file migration created for it.
func removeStagedSQLiteSidecars(stagedDB string) error {
	if err := removeStaleSQLiteSidecars(stagedDB); err != nil {
		return err
	}
	if err := os.Remove(stagedDB + ".migration.lock"); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func removeStaleSQLiteSidecars(dbPath string) error {
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(dbPath + suffix); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// refuseExistingKeySetManifest is refuseNonEmptyExisting for the key-set
// manifest (#2900): restore installs a new one with the key files, and
// without --overwrite-existing it is linked into place like them, which fails
// on an existing file. Refused here, before anything is staged, rather than
// at install, after the data has committed.
func refuseExistingKeySetManifest(cfg *config.Config) error {
	path, err := keySetManifestPath(cfg)
	if err != nil {
		return fmt.Errorf("key-set manifest: %w", err)
	}
	if path == "" {
		return nil
	}
	return refuseNonEmptyExisting("key-set manifest", path)
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

// writeRestoredFile atomically writes data to path -- see prepareRestoredFile
// and commitRestoredFile, which this just runs back-to-back for a single
// file. A multi-file SET (the key-material files restored together) is staged
// with prepareRestoredKeySet and installed from the restore journal instead
// (restore_commit.go).
func writeRestoredFile(path string, data []byte, restoreTS string) error {
	tmpPath, err := prepareRestoredFile(path, data)
	if err != nil {
		return err
	}
	return commitRestoredFile(path, tmpPath, restoreTS, restoreOverwriteExisting)
}

// prepareRestoredFile writes data to a temp file in path's directory and
// fsyncs it, without touching path itself -- the half of writeRestoredFile
// that can be run for an entire file SET before any of them commit (see
// prepareRestoredFileSet). On any error the temp file is removed and "" is
// returned; on success, the caller owns cleanup of the returned temp path
// (commitRestoredFile removes it as part of installing, or the caller must
// os.Remove it directly if abandoning the prepare).
func prepareRestoredFile(path string, data []byte) (string, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return "", fmt.Errorf("create directory: %w", err)
	}

	// #nosec G304 -- path is either this config's own database path or one
	// returned by keyfiles.Registry (already SafePath-sanitized) and, for key
	// files, already matched 1:1 against the archive manifest by
	// validateKeyFileSetV1/V2 -- never an attacker-controlled path from the archive.
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".restoring-*")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("fsync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, restoreFileMode); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("set file mode: %w", err)
	}
	return tmpPath, nil
}

// commitRestoredFile installs tmpPath (an already-written-and-fsynced temp
// file from prepareRestoredFile, in the same directory as path) at path --
// renamed (or, without --overwrite-existing, hard-linked -- see below) into
// place, then fsyncs the directory. Always writes restoreFileMode (0600),
// never whatever mode the archive's manifest recorded -- a crafted manifest
// must never be able to make a restored key/DB file group- or
// world-readable.
//
// With overwrite (--overwrite-existing), an existing file at path is renamed aside to
// "<path>.pre-restore-<restoreTS>" (never truncated or overwritten in
// place) before the new file is renamed in, so an unrecoverable mistake
// during an --overwrite-existing restore still has a way back. Without it,
// the new file is hard-linked into place instead of renamed: os.Link fails
// atomically with EEXIST if path already exists, closing the window between
// refuseNonEmptyExisting's earlier check and this write during which
// another process could have created path (os.Rename has no portable
// no-clobber option and would silently replace it).
func commitRestoredFile(path, tmpPath, restoreTS string, overwrite bool) error {
	dir := filepath.Dir(path)
	// No-op once renamed/linked into place below.
	defer os.Remove(tmpPath) //nolint:errcheck

	if overwrite {
		if _, err := os.Stat(path); err == nil {
			aside := fmt.Sprintf("%s.pre-restore-%s", path, restoreTS)
			if err := os.Rename(path, aside); err != nil {
				return fmt.Errorf("move existing %q aside to %q: %w", path, aside, err)
			}
			if err := restoreStepHook("moved-aside"); err != nil {
				return err
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

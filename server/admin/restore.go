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
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
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
	restoreAllowRollback     bool
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

Rollback protection (design-b3-backup-v2.md §6): restoring an OLDER backup
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

Only local/sqlite storage is supported today. For a Postgres-backed
deployment, restore with psql directly (see docs/SELF_HOSTING.md §5).`,
	RunE: runAdminRestore,
}

func init() {
	restoreCmd.Flags().StringVar(&restoreInput, "input", "", "Path to the backup archive to restore from (required)")
	restoreCmd.Flags().BoolVar(&restoreOverwriteExisting, "overwrite-existing", false, "Overwrite an existing, non-empty database or key file (dangerous)")
	restoreCmd.Flags().BoolVar(&restoreAllowRollback, "allow-rollback", false, "Proceed even though this backup is behind this host's own audit trail (dangerous -- see the rollback-protection note above)")
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

	// Rollback protection (design-b3-backup-v2.md §6.3) -- BEFORE any write to
	// disk below, so a refused restore never touches the target at all.
	//
	// The witness file alone only advances on a checkpoint (scheduled, default
	// every 24h, or on-demand) or a prior restore -- a change made to THIS
	// EXACT destination database since the last checkpoint (the literal repro
	// this feature closes: back up, create a secret, restore the OLDER backup
	// moments later, all well within one checkpoint interval) would not have
	// touched the witness at all, leaving nothing to detect it. The
	// destination database being overwritten right now is always live and
	// current, with no checkpoint delay -- reading its OWN raw audit-event
	// count, when --overwrite-existing means there IS an existing one, closes
	// that gap directly. destinationFloor is 0 (no additional floor) whenever
	// there is no pre-existing destination database to read.
	destinationFloor, err := readExistingDatabaseAuditEventCount(dbPath)
	if err != nil {
		return fmt.Errorf("read existing destination database's audit event count: %w", err)
	}
	// Compare like with like: the destination's raw audit_events count against
	// the ARCHIVED database's own raw count (read from the archive bytes, not
	// the manifest), and the witness's signed high-water against the
	// archive's signed high-water. Mixing them (raw destination count vs the
	// archive's signed high-water, which lags until a checkpoint runs) refused
	// a restore of a backup taken seconds earlier from the same database.
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

	// design-b3-backup-v2.md §6.3: advance the witness file to at least the
	// just-restored archive's own high-water mark, so a SUBSEQUENT restore on
	// this host compares against what actually landed on disk, not stale
	// pre-restore state. Best-effort -- a failure here degrades this host's
	// own future rollback detection, but the restore itself already
	// succeeded and must not be reported as failed over it.
	if rollbackCheck.archiveEncoded != "" {
		if _, werr := auditverify.WriteWitnessIfHigher(auditverify.WitnessPath(dbPath), rollbackCheck.archiveEncoded); werr != nil {
			fmt.Printf("note: could not update the rollback-protection witness file: %v\n", werr)
		}
	}
	// An allowed rollback needs its own explicit audit trail entry, written
	// once the restored chain is writable again (design-b3-backup-v2.md
	// §6.2: "using it writes an audit event recording that the override was
	// used" -- there is no silent, warning-only path).
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
// gap (for the audit event runAdminRestore writes once the restored chain
// is writable again), and the archive's own raw encoded high-water value
// (so runAdminRestore can advance the witness file to it after a successful
// restore, without re-parsing the manifest).
type rollbackCheckOutcome struct {
	overrodeRollback bool
	gapEvents        int64
	archiveEncoded   string
}

// checkRollbackProtection implements design-b3-backup-v2.md §6.3: compares
// the archive's own certified audit-trail progress (highWaterEncoded, from
// backupManifest.AuditHighWater -- empty if the source install had never
// written a checkpoint) against this host's witness file (sibling to dbPath,
// maintained by every server this host has run) BEFORE the caller writes
// anything to disk. Returns an error (refusing the restore) if the archive
// is behind and --allow-rollback was not given; any note worth printing is
// returned alongside a nil error otherwise.
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
	if highWaterEncoded != "" {
		archiveCP, _, ok := auditverify.ParseHighWater(highWaterEncoded)
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
	if found && witnessCP.ChainedEvents > archiveSigned && witnessCP.ChainedEvents-archiveSigned > gap {
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

// auditEventCountFromDBBytes returns MAX(audit_events.id) of an archived
// SQLite database image, read from a private temp copy (0 when the table is
// absent, e.g. an archive from an install that never logged an event).
func auditEventCountFromDBBytes(data []byte) (int64, error) {
	dir, err := os.MkdirTemp("", "keyorix-restore-audit-*")
	if err != nil {
		return 0, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(dir) //nolint:errcheck
	p := filepath.Join(dir, "archive.db")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return 0, fmt.Errorf("write temp copy: %w", err)
	}
	return readExistingDatabaseAuditEventCount(p)
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

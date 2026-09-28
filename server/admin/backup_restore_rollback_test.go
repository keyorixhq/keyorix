// backup_restore_rollback_test.go exercises design-b3-backup-v2.md §6.3's
// rollback protection through admin restore's real cobra RunE, the same
// shape backup_restore_integration_test.go uses for the round-trip case.
//
// Not t.Parallel() (this package's convention, see that file's own doc
// comment) -- these tests mutate package-level cobra flag vars.
package admin

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/config"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
)

// minimalValidSQLiteBytes returns the bytes of a genuine, minimal SQLite
// database file -- unlike an arbitrary byte string, this is required for a
// test that expects restore to proceed PAST the rollback check into the
// real migration step (storage.NewStorageFactory().CreateStorage opens it
// for real). Tests that expect restore to be REFUSED before that point
// don't need this -- the rollback check runs before the archive's own DB
// bytes are ever opened.
func minimalValidSQLiteBytes(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "minimal.db")
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	_, err = db.Exec("CREATE TABLE t(id INTEGER)")
	require.NoError(t, err)
	require.NoError(t, db.Close())
	data, err := os.ReadFile(path) // #nosec G304 -- our own just-created temp file
	require.NoError(t, err)
	return data
}

// seedRollbackTestArchive builds a minimal backup archive (a genuine SQLite
// db + no key files, matching buildTestManifest's own shape) whose manifest
// carries highWaterEvents as its recorded audit high-water mark (or leaves
// AuditHighWater unset when highWaterEvents < 0), and returns the archive's
// path.
func seedRollbackTestArchive(t *testing.T, dir string, highWaterEvents int64) string {
	t.Helper()
	dbData := minimalValidSQLiteBytes(t)
	manifest := buildTestManifest(dbData, nil)
	if highWaterEvents >= 0 {
		cp := &auditverify.Checkpoint{ChainedEvents: highWaterEvents, HeadID: 1, HeadHash: "aa", KeyVersion: "v1"}
		manifest.AuditHighWater = auditverify.EncodeHighWater(cp, "placeholder-sig")
	}
	archivePath := filepath.Join(dir, "backup.tar.gz")
	require.NoError(t, writeBackupArchive(archivePath, manifest, dbData, nil))
	return archivePath
}

// setUpRollbackRestoreTarget prepares a fresh restore-target directory
// (config + chdir) and returns its config path and DB path. Deliberately
// writes a config with NO encryption key-file paths configured (unlike
// writeBackupRestoreTestConfig, which the round-trip test uses) --
// keyfiles.Registry then expects zero key files, matching
// seedRollbackTestArchive's own db-only manifest (nil key files). These
// tests are about the rollback comparison, not key-file handling, which
// backup_restore_integration_test.go already covers.
func setUpRollbackRestoreTarget(t *testing.T) (cfgPath, dbPath string) {
	t.Helper()
	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	dbPath = filepath.Join(dstDir, "secrets.db")
	cfgPath = filepath.Join(dstDir, "keyorix.yaml")
	content := fmt.Sprintf("storage:\n  type: local\n  database:\n    path: %s\n", dbPath)
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0600))
	return cfgPath, dbPath
}

// TestAdminRestore_RefusesRollback_WithoutOverride is the exact repro this
// item was opened for: a backup taken at a lower audit high-water mark than
// this host has already progressed past must be refused, and refused BEFORE
// anything is written to disk -- not silently restored with the newer state
// undone.
func TestAdminRestore_RefusesRollback_WithoutOverride(t *testing.T) {
	resetBackupRestoreFlags(t)

	cfgPath, dbPath := setUpRollbackRestoreTarget(t)
	configPathFlag = cfgPath

	// This host has already certified 100 audit events (e.g. a revocation
	// recorded after the backup below was taken).
	witnessPath := auditverify.WitnessPath(dbPath)
	hostCP := &auditverify.Checkpoint{ChainedEvents: 100, HeadID: 5, HeadHash: "bb", KeyVersion: "v1"}
	_, err := auditverify.WriteWitnessIfHigher(witnessPath, auditverify.EncodeHighWater(hostCP, "sig"))
	require.NoError(t, err)

	// The backup archive is only at 10 events -- 90 events behind.
	restoreInput = seedRollbackTestArchive(t, t.TempDir(), 10)
	restoreOverwriteExisting = false
	restoreAllowRollback = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0

	err = runAdminRestore(nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "refusing to restore")
	require.Contains(t, err.Error(), "90 event(s) BEHIND")

	_, statErr := os.Stat(dbPath)
	require.True(t, os.IsNotExist(statErr), "a refused restore must not have written the database file at all")
}

// TestAdminRestore_AllowsRollback_WithOverride proves --allow-rollback lets
// the exact scenario above proceed, and that doing so writes an explicit
// audit event recording the override and the size of the gap, once the
// restored chain is writable again (design-b3-backup-v2.md §6.2: "there is
// no silent, warning-only path").
func TestAdminRestore_AllowsRollback_WithOverride(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())

	cfgPath, dbPath := setUpRollbackRestoreTarget(t)
	configPathFlag = cfgPath

	witnessPath := auditverify.WitnessPath(dbPath)
	hostCP := &auditverify.Checkpoint{ChainedEvents: 100, HeadID: 5, HeadHash: "bb", KeyVersion: "v1"}
	_, err := auditverify.WriteWitnessIfHigher(witnessPath, auditverify.EncodeHighWater(hostCP, "sig"))
	require.NoError(t, err)

	restoreInput = seedRollbackTestArchive(t, t.TempDir(), 10)
	restoreOverwriteExisting = false
	restoreAllowRollback = true
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0

	err = runAdminRestore(nil, nil)
	require.NoError(t, err)

	_, statErr := os.Stat(dbPath)
	require.NoError(t, statErr, "an allowed rollback restore must actually write the database file")

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	st, err := storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	action := "admin.restore_rollback_override"
	events, _, err := st.GetAuditLogs(context.Background(), &corestorage.AuditFilter{Action: &action})
	require.NoError(t, err)
	require.Len(t, events, 1, "exactly one override audit event must be written")
	require.Contains(t, events[0].Description, "90")
}

// TestAdminRestore_FreshHost_NoWitness_Proceeds proves the legitimate
// bootstrap case (design-b3-backup-v2.md §6.3): a target with no witness
// file at all (a genuinely fresh host, or the first restore ever run here)
// has nothing to compare against, so restore proceeds without
// --allow-rollback -- and the witness file is created afterward so a
// SUBSEQUENT restore on this same host IS protected.
func TestAdminRestore_FreshHost_NoWitness_Proceeds(t *testing.T) {
	resetBackupRestoreFlags(t)

	cfgPath, dbPath := setUpRollbackRestoreTarget(t)
	configPathFlag = cfgPath

	witnessPath := auditverify.WitnessPath(dbPath)
	_, statErr := os.Stat(witnessPath)
	require.True(t, os.IsNotExist(statErr), "sanity: no witness file must exist yet on this fresh target")

	restoreInput = seedRollbackTestArchive(t, t.TempDir(), 10)
	restoreOverwriteExisting = false
	restoreAllowRollback = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0

	require.NoError(t, runAdminRestore(nil, nil))

	cp, _, found, err := auditverify.ReadWitness(witnessPath)
	require.NoError(t, err)
	require.True(t, found, "restore must write the witness file for a fresh host, protecting the NEXT restore here")
	require.Equal(t, int64(10), cp.ChainedEvents)
}

// TestAdminRestore_NewerOrEqualArchive_Proceeds proves the archive-at-least-
// as-current case: no rollback is happening, so restore proceeds normally
// without needing --allow-rollback.
func TestAdminRestore_NewerOrEqualArchive_Proceeds(t *testing.T) {
	resetBackupRestoreFlags(t)

	cfgPath, dbPath := setUpRollbackRestoreTarget(t)
	configPathFlag = cfgPath

	witnessPath := auditverify.WitnessPath(dbPath)
	hostCP := &auditverify.Checkpoint{ChainedEvents: 10, HeadID: 1, HeadHash: "aa", KeyVersion: "v1"}
	_, err := auditverify.WriteWitnessIfHigher(witnessPath, auditverify.EncodeHighWater(hostCP, "sig"))
	require.NoError(t, err)

	// Archive is at the SAME high-water mark (10) -- not behind.
	restoreInput = seedRollbackTestArchive(t, t.TempDir(), 10)
	restoreOverwriteExisting = false
	restoreAllowRollback = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0

	require.NoError(t, runAdminRestore(nil, nil))
	_, statErr := os.Stat(dbPath)
	require.NoError(t, statErr)
}

// TestAdminRestore_NoRecordedHighWater_TreatedAsBehind proves an old-format
// archive (no AuditHighWater ever recorded -- predates this feature, or the
// source install had never written a checkpoint) is treated as ChainedEvents
// 0 against a target that HAS progressed, refusing by default rather than
// assuming the unknown quantity is safe.
func TestAdminRestore_NoRecordedHighWater_TreatedAsBehind(t *testing.T) {
	resetBackupRestoreFlags(t)

	cfgPath, dbPath := setUpRollbackRestoreTarget(t)
	configPathFlag = cfgPath

	witnessPath := auditverify.WitnessPath(dbPath)
	hostCP := &auditverify.Checkpoint{ChainedEvents: 5, HeadID: 1, HeadHash: "aa", KeyVersion: "v1"}
	_, err := auditverify.WriteWitnessIfHigher(witnessPath, auditverify.EncodeHighWater(hostCP, "sig"))
	require.NoError(t, err)

	// -1 tells seedRollbackTestArchive to leave AuditHighWater unset.
	restoreInput = seedRollbackTestArchive(t, t.TempDir(), -1)
	restoreOverwriteExisting = false
	restoreAllowRollback = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0

	err = runAdminRestore(nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "refusing to restore")
}

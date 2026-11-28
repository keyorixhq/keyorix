// restore_replace_existing_data_test.go: the --replace-existing-data guard's
// typed refusal and its flag (KEY-ROTATION-SAFETY-1 item 1). The byte-identity
// oracle for the refusal is restore_populated_refusal_test.go.
//
// Not t.Parallel(): package-level cobra flag vars and chdir.
package admin

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// The refusal is typed, so callers and scripts can tell it from a failed load.
func TestAdminRestore_OverwriteExisting_PopulatedTarget_RefusalIsTyped(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", populatedTargetPassphrase)

	archive, _, _, _, _ := populatedSQLiteRestoreCase(t)
	restoreInput = archive
	restoreOverwriteExisting = true
	restoreMaxEntryBytes, restoreMaxTotalBytes = 0, 0
	_, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.ErrorIs(t, err, ErrRestoreTargetPopulated)
}

// With both flags the populated SQLite target is replaced: the archive's keys
// and rows, the old database and key files kept aside.
func TestAdminRestore_SQLite_ReplaceExistingData_ReplacesPopulatedTarget(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", populatedTargetPassphrase)

	archive, dstCfg, src, tgt, dbPath := populatedSQLiteRestoreCase(t)
	oldDBSum := fileSHA256(t, dbPath)
	restoreInput = archive
	restoreOverwriteExisting, restoreReplaceExistingData = true, true
	restoreMaxEntryBytes, restoreMaxTotalBytes = 0, 0
	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "output was:\n%s", out)

	db, err := storage.OpenGormDB(dstCfg)
	require.NoError(t, err)
	defer closeGormDB(db)
	var users []models.User
	require.NoError(t, db.Find(&users).Error)
	require.Len(t, users, 1)
	require.Equal(t, "src-user", users[0].Username)
	aside, err := filepath.Glob(dbPath + ".pre-restore-*")
	require.NoError(t, err)
	found := false
	for _, p := range aside {
		found = found || fileSHA256(t, p) == oldDBSum
	}
	require.True(t, found, "the replaced database must be kept aside byte-identical (aside files: %v)", aside)
	src.dir = tgt.dir
	requireTargetUsable(t, dstCfg, src, "src")
}

// --replace-existing-data alone is refused: it qualifies --overwrite-existing.
func TestAdminRestore_ReplaceExistingData_WithoutOverwriteIsRefused(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", populatedTargetPassphrase)

	archive, _, _, tgt, dbPath := populatedSQLiteRestoreCase(t)
	oldKeys, oldDBSum := readKeyFiles(t, tgt.dir), fileSHA256(t, dbPath)
	restoreInput = archive
	restoreOverwriteExisting, restoreReplaceExistingData = false, true
	restoreMaxEntryBytes, restoreMaxTotalBytes = 0, 0
	_, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.Error(t, err)
	require.Equal(t, oldKeys, readKeyFiles(t, tgt.dir))
	require.Equal(t, oldDBSum, fileSHA256(t, dbPath))
}

// The re-run case --overwrite-existing exists for still passes without the new
// flag: a migrated, empty SQLite database (rows only in system_metadata).
func TestAdminRestore_SQLite_OverwriteExisting_EmptyMigratedTarget_NotPopulated(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	dir := t.TempDir()
	chdirTest(t, dir)
	initTargetKeys(t, dir)
	dbPath := filepath.Join(dir, "secrets.db")
	configPathFlag = writeBackupRestoreTestConfig(t, dir, dbPath)
	cfg, err := loadConfig()
	require.NoError(t, err)
	st, err := createStorageClosedAtCleanup(t, cfg)
	require.NoError(t, err)
	closeTestStorage(st)

	tables, err := restoreTargetTablesWithRows(cfg, dbPath)
	require.NoError(t, err)
	require.Empty(t, tables, "a freshly migrated database holds no data")
	restoreOverwriteExisting = true
	require.NoError(t, refusePopulatedRestoreTarget(cfg, dbPath))

	// An admin command run on the fresh host (here: what a rolled-back
	// restore --recover records) is bookkeeping, not data.
	recordAdminAction(cfg, "admin.restore_recovered", "rolled back an interrupted restore", true)
	tables, err = restoreTargetTablesWithRows(cfg, dbPath)
	require.NoError(t, err)
	require.Empty(t, tables, "admin_cli audit events are not deployment data")

	// Any other audit event is.
	db, err := storage.OpenGormDB(cfg)
	require.NoError(t, err)
	ok := true
	require.NoError(t, db.Create(&models.AuditEvent{EventType: "user.revoked", Success: &ok, EventTime: time.Now()}).Error)
	closeGormDB(db)
	tables, err = restoreTargetTablesWithRows(cfg, dbPath)
	require.NoError(t, err)
	require.Equal(t, []string{"audit_events"}, tables)
	require.ErrorIs(t, refusePopulatedRestoreTarget(cfg, dbPath), ErrRestoreTargetPopulated)
}

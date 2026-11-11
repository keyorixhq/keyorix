// backup_stale_salt_pending_test.go (C2, H2): an interrupted rotate-kek that did
// NOT change the active keys leaves kek.salt.pending. A successful server start
// (ReconcileKeySet) proves the active set opens and leaves that file in place
// with a warning only (it is unused). But refusePendingKeyRotation
// (server/admin/backup.go) refuses EVERY later `admin backup` while any
// <salt_path>.pending exists, so a backup outage persists until an operator
// deletes the file by hand. Under cron (stderr discarded, exit code unchecked)
// this is a silent backup outage.
//
// This test demonstrates the end-to-end consequence on the REAL admin backup
// path and characterizes how loudly it is reported:
//   - exit code: non-zero (runAdminBackup returns an error).
//   - message/stderr: names the pending file and the "delete that file" advice.
//   - audit event: none is structurally possible -- refusePendingKeyRotation
//     runs at the very top of runAdminBackup (backup.go:244), before storage or
//     the audit log is opened, so a refused backup leaves no audit trail.
//
// The companion file-level evidence (boot leaves kek.salt.pending for good) is
// internal/encryption/keyset_pending_backup_test.go
// (TestRotateKEKCrashPoints_PendingFilesBackupRefusesOn, the
// "kek:after-write-salt-pending" case). Default CI (SQLite; the file side is
// identical on PostgreSQL).
package admin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/storage"
)

func h2WriteSQLiteConfig(t *testing.T, dir string) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	content := "storage:\n" +
		"  type: sqlite\n" +
		"  database:\n" +
		"    path: " + filepath.Join(dir, "keyorix.db") + "\n" +
		"  encryption:\n" +
		"    enabled: true\n" +
		"    dek_path: dek.key\n" +
		"    salt_path: kek.salt\n"
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0o600))
	return cfgPath
}

func TestAdminBackup_StaleSaltPending_RefusesEveryBackupUntilDeleted(t *testing.T) {
	const pass = "h2-master-passphrase-0001"
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", pass)

	dir := t.TempDir()
	chdirTest(t, dir)
	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	require.NoError(t, encryption.NewService(encCfg, dir).Initialize(pass))

	configPathFlag = h2WriteSQLiteConfig(t, dir)
	cfg, err := loadConfig()
	require.NoError(t, err)
	_, err = storage.NewStorageFactory().CreateStorage(cfg) // migrate the SQLite schema
	require.NoError(t, err)

	saltPending := filepath.Join(dir, "kek.salt.pending")

	// Stage a stale kek.salt.pending: the leftover of a rotate-kek interrupted
	// before it changed the active keys. refusePendingKeyRotation stats the file
	// only, so its content is immaterial; a staged salt is just bytes.
	require.NoError(t, os.WriteFile(saltPending, []byte("stale-staged-salt-bytes"), 0o600))

	// === a SUCCESSFUL server start leaves the stale salt in place ===
	boot := encryption.NewService(encCfg, dir)
	require.NoError(t, boot.AcquireExclusiveKeyLock())
	// ReconcileKeySet models the boot key-reconcile step: it must SUCCEED (the
	// active set is coherent) and must LEAVE the stale salt (it only warns).
	require.NoError(t, boot.ReconcileKeySet(), "boot reconcile must succeed with a coherent active key set")
	require.NoError(t, boot.RecoverInterruptedRotation(nil))
	boot.Shutdown()
	_, statErr := os.Stat(saltPending)
	require.NoError(t, statErr, "a successful boot must leave kek.salt.pending in place (it is left with a warning, not removed)")

	// Confirm PendingRotationFiles still reports it (what backup refuses on).
	pending, err := keyfiles.PendingRotationFiles(&cfg.Storage.Encryption, dir)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.True(t, pending[0].Salt)

	// === every later admin backup is refused ===
	for i := 1; i <= 2; i++ {
		archivePath := filepath.Join(t.TempDir(), "h2-backup.tar.gz")
		backupOutput = archivePath
		out, backupErr := captureStdout(t, func() error { return runAdminBackup(nil, nil) })

		require.Error(t, backupErr, "backup #%d must be refused while kek.salt.pending exists:\n%s", i, out)
		// Loudness: the message names the file and the manual-delete remedy.
		require.Contains(t, backupErr.Error(), "kek.salt.pending")
		require.Contains(t, backupErr.Error(), "delete that file")
		// No archive was written (fail-closed).
		_, archStat := os.Stat(archivePath)
		require.True(t, os.IsNotExist(archStat), "a refused backup must write no archive")
		t.Logf("backup #%d refused (exit non-zero), no archive: %v", i, backupErr)
	}

	// === the ONLY remedy is deleting the file by hand; then backup succeeds ===
	require.NoError(t, os.Remove(saltPending))
	archivePath := filepath.Join(t.TempDir(), "h2-backup-after-delete.tar.gz")
	backupOutput = archivePath
	out, backupErr := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.NoError(t, backupErr, "after deleting kek.salt.pending the backup must succeed:\n%s", out)
	fi, statErr := os.Stat(archivePath)
	require.NoError(t, statErr)
	require.Greater(t, fi.Size(), int64(0))
}

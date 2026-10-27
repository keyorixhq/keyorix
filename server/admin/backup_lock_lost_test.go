package admin

// SERVERGUARD-LOCK-TAILS-1 item 2: a backup whose lock is lost while it runs
// leaves no archive and exits non-zero, saying the backup is not usable. The
// archive is written in place (O_EXCL), so a stop must remove it.
//
// This file: SQLite, where the backup holds the exclusive lock and its loss is
// real (the <database>.server.lock sidecar is deleted, item 1's watch notices
// and stopOnLostDatabaseLock stops the command; os.Exit is observed instead),
// and the harness both lock kinds share. The three loss points:
// backup_lock_lost_points_test.go.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
)

// resetBackupSeams clears the archive write seam and the --exclusive flag after the test.
func resetBackupSeams(t *testing.T) {
	t.Helper()
	oldExclusive := backupExclusive
	t.Cleanup(func() {
		backupOutputWriteHook = nil
		backupExclusive = oldExclusive
	})
}

// captureStderr runs fn with os.Stderr sent to a file and returns what it wrote.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	f, err := os.Create(filepath.Join(t.TempDir(), "stderr"))
	require.NoError(t, err)
	old := os.Stderr
	os.Stderr = f
	func() {
		defer func() { os.Stderr = old }()
		fn()
	}()
	require.NoError(t, f.Close())
	b, err := os.ReadFile(f.Name())
	require.NoError(t, err)
	return string(b)
}

// runBackupCommand runs `admin backup` through Execute, as the binary does.
func runBackupCommand(t *testing.T, archivePath string) (code int, stderr string) {
	t.Helper()
	stderr = captureStderr(t, func() {
		_, _ = captureStdout(t, func() error {
			code = Execute([]string{"backup", "--config", configPathFlag, "--output", archivePath})
			return nil
		})
	})
	return code, stderr
}

// sqliteBackupSource is an encrypted SQLite deployment in a fresh directory
// (the process is moved into it), with a fast sidecar watch.
func sqliteBackupSource(t *testing.T) (lockPath string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-passphrase-1234")
	srcDir := t.TempDir()
	chdirTest(t, srcDir)
	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	require.NoError(t, encryption.NewService(encCfg, srcDir).Initialize("test-passphrase-1234"))
	dbPath := filepath.Join(srcDir, "secrets.db")
	configPathFlag = writeBackupRestoreTestConfig(t, srcDir, dbPath)
	cfg, err := loadConfig()
	require.NoError(t, err)
	_, err = storage.NewStorageFactory().CreateStorage(cfg) // creates + migrates the source database
	require.NoError(t, err)
	old := config.PinnedLockPingInterval
	config.PinnedLockPingInterval = 20 * time.Millisecond
	t.Cleanup(func() { config.PinnedLockPingInterval = old })
	return dbPath + ".server.lock"
}

// TestAdminBackup_SQLiteLockLostMidStream_RemovesTheArchive: the lock file is
// deleted after the first chunk of the archive is on disk. The command is
// stopped (os.Exit in production, which skips every defer), and the partial
// archive must be gone by then: a later point of the same run cannot remove
// it. Before SERVERGUARD-LOCK-TAILS-1 the exclusive path ignored the loss and
// finished the archive (and an os.Exit would have left the partial one).
func TestAdminBackup_SQLiteLockLostMidStream_RemovesTheArchive(t *testing.T) {
	resetBackupRestoreFlags(t)
	resetBackupSeams(t)
	lockPath := sqliteBackupSource(t)
	exited := observeLostLockExit(t)
	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	writes := 0
	var atExit error
	backupOutputWriteHook = func() {
		if writes++; writes != 1 {
			return
		}
		require.NoError(t, os.Remove(lockPath))
		select {
		case <-exited: // in production the process ends here, exit status 1
			_, atExit = os.Stat(archivePath)
		case <-time.After(10 * time.Second):
			t.Fatal("the backup's lock file was deleted, but the command was not stopped")
		}
	}

	code, stderr := runBackupCommand(t, archivePath)
	require.True(t, os.IsNotExist(atExit), "the partial archive was still on disk when the command was stopped (stat err %v); stderr:\n%s", atExit, stderr)
	require.NotZero(t, code, "stderr:\n%s", stderr)
	_, statErr := os.Stat(archivePath)
	require.True(t, os.IsNotExist(statErr), "an archive remains after the lock was lost (stat err %v)", statErr)
	require.Contains(t, stderr, "not usable")
}

// The control: the same harness without a loss writes the archive and exits 0.
func TestAdminBackup_SQLiteLockHeld_ArchiveWritten(t *testing.T) {
	resetBackupRestoreFlags(t)
	resetBackupSeams(t)
	sqliteBackupSource(t)
	exited := observeLostLockExit(t)
	writes := 0
	backupOutputWriteHook = func() { writes++ }

	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	code, stderr := runBackupCommand(t, archivePath)
	require.Zero(t, code, "stderr:\n%s", stderr)
	require.Positive(t, writes, "the archive must be written through the lock watch")
	fi, err := os.Stat(archivePath)
	require.NoError(t, err)
	require.Positive(t, fi.Size())
	require.False(t, strings.Contains(stderr, "not usable"), stderr)
	select {
	case <-exited:
		t.Fatal("a backup whose lock was held was stopped")
	default:
	}
}

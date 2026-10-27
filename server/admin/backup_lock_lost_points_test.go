package admin

// SERVERGUARD-LOCK-TAILS-1 item 2: a backup whose lock is lost leaves no
// archive and exits non-zero, saying the backup is not usable, at every point
// of the write: before the first byte, mid-stream, and after the last byte but
// before the file is closed. SQLite (exclusive lock, real loss) here; the live
// PostgreSQL presence lock in backup_lock_lost_postgres_test.go.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// backupLossPoints are the three places a lock loss is injected. arm installs
// the seam that calls lose at that point.
var backupLossPoints = []struct {
	name string
	arm  func(lose func())
}{
	{"before the first byte", func(lose func()) {
		backupOutputStageHook = func(stage string) {
			if stage == backupStageCreated {
				lose()
			}
		}
	}},
	{"mid-stream", func(lose func()) {
		writes := 0
		backupOutputWriteHook = func() {
			if writes++; writes == 1 {
				lose()
			}
		}
	}},
	{"after the last byte, before close", func(lose func()) {
		backupOutputStageHook = func(stage string) {
			if stage == backupStageBeforeClose {
				lose()
			}
		}
	}},
}

// armBackupLossPoint installs point's seam and clears both seams after the test.
func armBackupLossPoint(t *testing.T, arm func(lose func()), lose func()) {
	t.Helper()
	t.Cleanup(func() { backupOutputWriteHook, backupOutputStageHook = nil, nil })
	arm(lose)
}

func TestAdminBackup_SQLiteLockLost_NoArchiveAndNonZeroExit(t *testing.T) {
	for _, point := range backupLossPoints {
		t.Run(point.name, func(t *testing.T) {
			resetBackupRestoreFlags(t)
			resetBackupSeams(t)
			lockPath := sqliteBackupSource(t)
			exited := observeLostLockExit(t)
			stopped := false
			armBackupLossPoint(t, point.arm, func() {
				if stopped {
					return
				}
				stopped = true
				require.NoError(t, os.Remove(lockPath))
				select {
				case <-exited: // in production the process ends here, exit status 1
				case <-time.After(10 * time.Second):
					t.Fatal("the backup's lock file was deleted, but the command was not stopped")
				}
			})

			archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
			code, stderr := runBackupCommand(t, archivePath)
			require.True(t, stopped, "the loss point %q was never reached", point.name)
			require.NotZero(t, code, "a backup whose lock was lost exited 0; stderr:\n%s", stderr)
			_, statErr := os.Stat(archivePath)
			require.True(t, os.IsNotExist(statErr), "an archive remains after the lock was lost %s (stat err %v); stderr:\n%s", point.name, statErr, stderr)
			require.Contains(t, stderr, "this backup is not usable", "the failure must say the backup is not usable")
			require.Contains(t, stderr, "exclusive database lock was lost")
		})
	}
}

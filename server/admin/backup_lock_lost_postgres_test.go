package admin

// SERVERGUARD-LOCK-TAILS-1 item 2, live PostgreSQL path: a live backup under
// key_dir_lock: database holds the shared server-presence lock. Its loss
// (Presence.Lost, injected through the fake) at each of the three points in
// backupLossPoints leaves no archive and a non-zero exit saying the backup is
// not usable. Gated on KEYORIX_TEST_PG_DSN.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/i18n"
)

func TestAdminBackup_Postgres_LivePresenceLost_NoArchiveAndNonZeroExit(t *testing.T) {
	for _, point := range backupLossPoints {
		t.Run(point.name, func(t *testing.T) {
			resetBackupRestoreFlags(t)
			resetBackupSeams(t)
			require.NoError(t, i18n.InitializeForTesting())
			t.Setenv("KEYORIX_MASTER_PASSWORD", liveTestPassphrase)
			pgLiveSource(t)
			fake := useFakeLiveBackupPresence(t)
			backupExclusive = false
			lost := false
			armBackupLossPoint(t, point.arm, func() { lost = true; fake.lose() })

			archivePath := filepath.Join(t.TempDir(), "live.tar.gz")
			code, stderr := runBackupCommand(t, archivePath)
			require.True(t, lost, "the loss point %q was never reached", point.name)
			require.NotZero(t, code, "a live backup whose presence lock was lost exited 0; stderr:\n%s", stderr)
			_, statErr := os.Stat(archivePath)
			require.True(t, os.IsNotExist(statErr), "an archive remains after the presence lock was lost %s (stat err %v)", point.name, statErr)
			require.Contains(t, stderr, "this backup is not usable")
			require.Contains(t, stderr, "the server-presence lock it holds (storage.encryption.key_dir_lock: database) was lost")
			require.True(t, fake.released, "the presence lock must still be released")
		})
	}
}

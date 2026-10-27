package admin

// The real-lock half of backup_presence_lost_postgres_test.go: no test seam, so
// it also runs against the code before the fix (where it fails). Gated on
// KEYORIX_TEST_PG_DSN.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// End to end with the real lock: the replicas recorded key_dir_lock: database,
// so the live backup takes the real presence lock; its backend is terminated
// after the database read (pg_terminate_backend, as a failover or an operator
// would). The backup must fail and leave no archive instead of reporting OK.
func TestAdminBackup_Postgres_RealPresenceLockLost_NoArchive(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", liveTestPassphrase)
	prevPing := config.PinnedLockPingInterval
	config.PinnedLockPingInterval = 10 * time.Millisecond
	t.Cleanup(func() { config.PinnedLockPingInterval = prevPing })

	cfg, enc, _, srcDir := pgLiveSource(t)
	dsn := cfg.Storage.Database.DSN
	db := pgAdminRawOpen(t, dsn)
	require.NoError(t, db.Create(&models.SystemMetadata{Key: config.KeyDirLockModeMetadataKey, Value: config.KeyDirLockDatabase}).Error)
	// A server holding dek.lock sends the backup down the live path, where the
	// after-read hook runs.
	svc := encryption.NewService(enc, srcDir)
	require.NoError(t, svc.AcquireExclusiveKeyLock())
	t.Cleanup(svc.Shutdown)

	backupLiveAfterReadHook = func() {
		killer := pgAdminRawOpen(t, dsn)
		var pids []int
		require.NoError(t, killer.Raw(`SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND objid = 872342 AND granted
			AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) AND pid <> pg_backend_pid()`).Scan(&pids).Error)
		require.Len(t, pids, 1, "exactly the backup's presence lock must be held")
		require.NoError(t, killer.Exec("SELECT pg_terminate_backend(?)", pids[0]).Error)
		// Let the lock's liveness ping (10 ms here) notice the dead backend.
		time.Sleep(500 * time.Millisecond)
	}
	t.Cleanup(func() { backupLiveAfterReadHook = nil })

	archivePath := filepath.Join(t.TempDir(), "live.tar.gz")
	backupOutput = archivePath
	backupExclusive = false
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.Error(t, err, "a backup whose presence lock was lost reported success:\n%s", out)
	require.Contains(t, err.Error(), "was lost while it ran")
	_, statErr := os.Stat(archivePath)
	require.True(t, os.IsNotExist(statErr), "a backup whose presence lock was lost must leave no archive, stat err = %v", statErr)
}

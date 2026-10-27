package admin

// A live PostgreSQL backup under key_dir_lock: database holds the shared
// server-presence lock so no key rotation or restore runs while it reads. If that
// lock is found lost mid-backup (Presence.Lost), the backup must not report an
// archive a rotation may have raced: it stops, removes the partial output file
// and fails with the reason (docs/design/pooler-lock-loss.md, "Not changed").
// Gated on KEYORIX_TEST_PG_DSN.

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/require"
)

// fakeLiveBackupPresence is a presence lock whose loss the test controls.
type fakeLiveBackupPresence struct {
	lost     chan struct{}
	once     sync.Once
	released bool
}

func (f *fakeLiveBackupPresence) Lost() <-chan struct{} { return f.lost }
func (f *fakeLiveBackupPresence) Release() error        { f.released = true; return nil }
func (f *fakeLiveBackupPresence) lose()                 { f.once.Do(func() { close(f.lost) }) }

func useFakeLiveBackupPresence(t *testing.T) *fakeLiveBackupPresence {
	t.Helper()
	fake := &fakeLiveBackupPresence{lost: make(chan struct{})}
	prev := acquireLiveBackupPresenceFn
	acquireLiveBackupPresenceFn = func(*config.Config) (liveBackupPresence, error) { return fake, nil }
	t.Cleanup(func() { acquireLiveBackupPresenceFn = prev; backupOutputWriteHook = nil })
	return fake
}

// The Lost channel closes after the first chunk of the archive is on disk: the
// backup stops, removes the partial file and fails, saying why.
func TestAdminBackup_Postgres_PresenceLostMidWrite_RemovesTheArchiveAndFails(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", liveTestPassphrase)
	pgLiveSource(t)
	fake := useFakeLiveBackupPresence(t)

	archivePath := filepath.Join(t.TempDir(), "live.tar.gz")
	backupOutput = archivePath
	backupExclusive = false
	writes := 0
	backupOutputWriteHook = func() {
		writes++
		if writes == 1 {
			fi, err := os.Stat(archivePath)
			require.NoError(t, err)
			require.Positive(t, fi.Size(), "the archive must be partly written when the lock is lost")
			fake.lose()
		}
	}
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.Error(t, err, "a backup whose presence lock was lost mid-write reported success:\n%s", out)
	require.Contains(t, err.Error(), "the server-presence lock it holds (storage.encryption.key_dir_lock: database) was lost")
	require.Contains(t, err.Error(), "The partial archive "+archivePath+" was removed")
	require.Equal(t, 1, writes, "no write may reach the archive after the lock is lost")
	_, statErr := os.Stat(archivePath)
	require.True(t, os.IsNotExist(statErr), "the partial archive must be removed, stat err = %v", statErr)
	require.True(t, fake.released, "the presence lock must still be released")
	require.NotContains(t, out, "Backup written to", "a stopped backup must not print the success line")
}

// The same backup with a presence lock that stays held succeeds: the watch
// itself does not break a live backup.
func TestAdminBackup_Postgres_PresenceHeld_BackupSucceeds(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", liveTestPassphrase)
	pgLiveSource(t)
	fake := useFakeLiveBackupPresence(t)
	writes := 0
	backupOutputWriteHook = func() { writes++ }

	archivePath := filepath.Join(t.TempDir(), "live.tar.gz")
	backupOutput = archivePath
	backupExclusive = false
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.NoError(t, err, "output:\n%s", out)
	require.Positive(t, writes, "the archive must be written through the presence watch")
	_, statErr := os.Stat(archivePath)
	require.NoError(t, statErr)
	require.True(t, fake.released)
}

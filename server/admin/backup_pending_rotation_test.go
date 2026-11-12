package admin

// #4058: `admin backup` is refused while a key rotation's .pending staging file
// exists, because the archive would carry it and `admin restore` would refuse
// that archive on any host without the same leftover. The states rotate-kek
// really leaves are pinned from the real rotation in internal/encryption
// (TestRotateKEKCrashPoints_PendingFilesBackupRefusesOn); here the staging files
// are planted, and everything downstream of them is the real command.

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
)

const (
	testDEKPending  = "dek.key.pending"
	testSaltPending = "kek.salt.pending"
)

// plantStagingFiles writes each named file in the current directory and
// returns its content.
func plantStagingFiles(t *testing.T, names ...string) map[string][]byte {
	t.Helper()
	planted := map[string][]byte{}
	for _, name := range names {
		data := make([]byte, 32)
		_, err := rand.Read(data)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(name, data, 0o600))
		planted[name] = data
	}
	return planted
}

// requireRefusedAndUntouched runs the backup and asserts the whole refusal: a
// non-zero exit, a message naming each file and the fix, nothing written to the
// output directory, and every key file exactly as it was.
func requireRefusedAndUntouched(t *testing.T, planted map[string][]byte) string {
	t.Helper()
	before := map[string][]byte{}
	for _, name := range []string{"dek.key", "kek.salt"} {
		data, err := os.ReadFile(name)
		require.NoError(t, err)
		before[name] = data
	}

	outDir := t.TempDir()
	code, stderr := runBackupCommand(t, filepath.Join(outDir, "backup.tar.gz"))

	require.NotZero(t, code, "a backup with a pending rotation must fail; stderr:\n%s", stderr)
	require.Contains(t, stderr, "a key rotation is running or was interrupted")
	require.Contains(t, stderr, "start the server once so boot recovery completes the rotation")
	require.Contains(t, stderr, "no archive was written")
	for name := range planted {
		require.Contains(t, stderr, name, "the refusal must name the file")
	}
	entries, err := os.ReadDir(outDir)
	require.NoError(t, err)
	require.Empty(t, entries, "a refused backup must leave nothing in the output directory")
	for _, files := range []map[string][]byte{before, planted} {
		for name, want := range files {
			got, err := os.ReadFile(name)
			require.NoError(t, err, "a refused backup must not remove %s", name)
			require.True(t, bytes.Equal(want, got), "a refused backup must not change %s", name)
		}
	}
	return stderr
}

func TestAdminBackup_RefusedWhileARotationIsPending(t *testing.T) {
	cases := []struct {
		name       string
		files      []string
		saltAdvice bool
	}{
		{"interrupted DEK rotation", []string{testDEKPending}, false},
		{"rotate-kek killed after staging the salt", []string{testSaltPending}, true},
		{"rotate-kek killed after staging both", []string{testSaltPending, testDEKPending}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resetBackupRestoreFlags(t)
			sqliteBackupSource(t)
			stderr := requireRefusedAndUntouched(t, plantStagingFiles(t, c.files...))
			if c.saltAdvice {
				require.Contains(t, stderr, "move it out of the key directory")
			} else {
				require.NotContains(t, stderr, "move it out of the key directory",
					"only an unused staging salt may ever be suggested for deletion")
			}
		})
	}
}

// rotate-kek killed between its two renames: dek.key is under the salt in
// kek.salt.pending, so the active pair opens with no passphrase. The refusal
// must still be the one that explains the state, not a wrong-passphrase error.
func TestAdminBackup_RefusedInTheRotateKEKHazardWindow(t *testing.T) {
	resetBackupRestoreFlags(t)
	sqliteBackupSource(t)
	require.NoError(t, os.Rename("kek.salt", testSaltPending))
	plantStagingFiles(t, "kek.salt")
	pending, err := os.ReadFile(testSaltPending)
	require.NoError(t, err)

	requireRefusedAndUntouched(t, map[string][]byte{testSaltPending: pending})
}

// The check under the key lock, on its own: a rotation killed after the
// command's first check is still refused by the read both backup paths share
// (the exclusive one and the live Postgres one).
func TestReadKeyFilesForBackup_RefusesAPendingRotation(t *testing.T) {
	resetBackupRestoreFlags(t)
	sqliteBackupSource(t)
	cfg, err := loadConfig()
	require.NoError(t, err)

	entries, _, err := readKeyFilesForBackup(cfg)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	plantStagingFiles(t, testDEKPending)
	_, _, err = readKeyFilesForBackup(cfg)
	require.ErrorContains(t, err, "a key rotation is running or was interrupted")
}

// recoverLikeBoot runs the two key-recovery steps server start runs, in order
// (server/boot_encryption.go).
func recoverLikeBoot(t *testing.T) {
	t.Helper()
	cfg, err := loadConfig()
	require.NoError(t, err)
	svc := encryption.NewService(&cfg.Storage.Encryption, ".")
	require.NoError(t, svc.AcquireExclusiveKeyLock())
	defer svc.Shutdown()
	require.NoError(t, svc.ReconcileKeySet())
	gdb, err := storage.OpenGormDB(cfg)
	require.NoError(t, err)
	defer closeGormDB(gdb)
	require.NoError(t, svc.RecoverInterruptedRotation(gdb))
}

// requireRestores restores archive into the current directory.
func requireRestores(t *testing.T, archive string, overwrite bool) {
	t.Helper()
	restoreInput = archive
	restoreOverwriteExisting = overwrite
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0
	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "output was:\n%s", out)
	require.Contains(t, out, "verify-audit on the restored database: VALID")
}

// The fix the refusal names works, and a refusal costs nothing: an archive
// taken before it still restores on the same host, and the backup taken after
// recovery restores on a clean one, which is the restore #4058 was refused.
func TestAdminBackup_RefusalThenRecovery_RestoresOnSameAndCleanHost(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		// mustDelete is what boot leaves and the refusal says to delete.
		mustDelete string
	}{
		{"DEK staging file is cleared by boot", []string{testDEKPending}, ""},
		{"abandoned staging salt survives boot", []string{testSaltPending}, testSaltPending},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resetBackupRestoreFlags(t)
			sqliteBackupSource(t)
			srcDir, err := os.Getwd()
			require.NoError(t, err)

			before := filepath.Join(t.TempDir(), "before.tar.gz")
			code, stderr := runBackupCommand(t, before)
			require.Zero(t, code, "a normal backup must work; stderr:\n%s", stderr)
			require.FileExists(t, before)

			requireRefusedAndUntouched(t, plantStagingFiles(t, c.files...))

			recoverLikeBoot(t)
			if c.mustDelete != "" {
				require.FileExists(t, c.mustDelete, "boot leaves an abandoned staging salt in place")
				require.NoError(t, os.Remove(c.mustDelete))
			}
			for _, name := range c.files {
				require.NoFileExists(t, name)
			}

			after := filepath.Join(t.TempDir(), "after.tar.gz")
			code, stderr = runBackupCommand(t, after)
			require.Zero(t, code, "the backup after recovery must work; stderr:\n%s", stderr)

			requireRestores(t, before, true)

			cleanHost := t.TempDir()
			require.NotEqual(t, srcDir, cleanHost)
			chdirTest(t, cleanHost)
			configPathFlag = writeBackupRestoreTestConfig(t, cleanHost, filepath.Join(cleanHost, "secrets.db"))
			requireRestores(t, after, false)
		})
	}
}

// The live (non-exclusive) Postgres path, where no database lock is taken and
// the key side can run beside a server.
func TestAdminBackup_Postgres_RefusedWhileARotationIsPending(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-passphrase-1234")
	dsn := pgAdminIsolatedDatabaseDSN(t, pgAdminTestDSN(t))
	dir := t.TempDir()
	chdirTest(t, dir)
	require.NoError(t, encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, dir).Initialize("test-passphrase-1234"))
	configPathFlag = writePostgresBackupRestoreTestConfig(t, dir, dsn)
	cfg, err := loadConfig()
	require.NoError(t, err)
	_, err = storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	backupExclusive = false

	requireRefusedAndUntouched(t, plantStagingFiles(t, testDEKPending))
}

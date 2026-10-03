// backup_restore_live_test.go covers DEMO-1's two disaster-recovery
// blockers at the command level, through the real cobra RunE functions:
//
//   - #2604 (default-ci, SQLite): `admin restore` onto a genuinely fresh,
//     EMPTY key directory configured with ABSOLUTE key paths (the Docker
//     image's /app/keys/... shape) must succeed. It used to fail with
//     "kek.salt was created concurrently during restore": restore's own
//     KEK-unwrap staging wrote the archive's key files straight into the
//     absolute target paths, and commitRestoredFile's concurrent-creation
//     guard then refused them.
//   - #2602 (pg-gated): on Postgres, `admin backup` beside a LIVE server
//     (which holds dek.lock exclusively and the database's advisory lock for
//     its lifetime) takes a live backup that restores correctly -- and
//     refuses, leaving no archive, whenever that could be inconsistent: a key
//     rotation in progress, the key files changing during the backup, or
//     --exclusive. On SQLite it refuses with an explicit "stop the server".
package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/serverguard"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const liveTestPassphrase = "test-passphrase-1234"

// writeAbsKeyPathsConfig writes a config whose key files live at ABSOLUTE
// paths in keysDir (keyorix.docker.yaml's shape), with storageYAML as the
// database block.
func writeAbsKeyPathsConfig(t *testing.T, dir, storageYAML, keysDir string) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	content := fmt.Sprintf(`storage:
%s  encryption:
    enabled: true
    dek_path: %q
    salt_path: %q
`, storageYAML, filepath.Join(keysDir, "data.key"), filepath.Join(keysDir, "kek.salt"))
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0600))
	return cfgPath
}

func absKeyEncCfg(keysDir string) *config.EncryptionConfig {
	return &config.EncryptionConfig{Enabled: true,
		DEKPath: filepath.Join(keysDir, "data.key"), SaltPath: filepath.Join(keysDir, "kek.salt")}
}

// emptyDir removes everything inside dir but keeps dir itself -- a fresh,
// empty, already-mounted volume.
func emptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		require.NoError(t, os.RemoveAll(filepath.Join(dir, e.Name())))
	}
}

func readKeyBytes(t *testing.T, keysDir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, name := range []string{"data.key", "kek.salt"} {
		b, err := os.ReadFile(filepath.Join(keysDir, name)) // #nosec G304 -- t.TempDir() path
		require.NoError(t, err)
		out[name] = b
	}
	return out
}

// TestAdminRestore_AbsoluteKeyPaths_FreshEmptyKeysDir is #2604 on SQLite.
func TestAdminRestore_AbsoluteKeyPaths_FreshEmptyKeysDir(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", liveTestPassphrase)

	keysDir := t.TempDir() // the keys volume
	srcDir := t.TempDir()
	chdirTest(t, srcDir)
	require.NoError(t, encryption.NewService(absKeyEncCfg(keysDir), srcDir).Initialize(liveTestPassphrase))

	srcDB := filepath.Join(srcDir, "secrets.db")
	configPathFlag = writeAbsKeyPathsConfig(t, srcDir, fmt.Sprintf("  type: local\n  database:\n    path: %s\n", srcDB), keysDir)
	srcCfg, err := loadConfig()
	require.NoError(t, err)
	_, err = storage.NewStorageFactory().CreateStorage(srcCfg)
	require.NoError(t, err)

	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	backupOutput = archivePath
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.NoError(t, err, "output was:\n%s", out)
	origKeys := readKeyBytes(t, keysDir)

	// Disaster: the host is gone. Same config, an EMPTY keys volume at the
	// same absolute path, a fresh data directory.
	emptyDir(t, keysDir)
	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	dstDB := filepath.Join(dstDir, "secrets.db")
	configPathFlag = writeAbsKeyPathsConfig(t, dstDir, fmt.Sprintf("  type: local\n  database:\n    path: %s\n", dstDB), keysDir)
	restoreInput = archivePath
	restoreOverwriteExisting = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0

	out, err = captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "restore onto a fresh, empty absolute-path keys dir must succeed; output was:\n%s", out)
	require.Equal(t, origKeys, readKeyBytes(t, keysDir), "restored key files must be byte-identical to the backed-up ones")
}

// TestAdminRestore_AbsoluteKeyPaths_NonEmptyKeysDirStillRefused: the fix
// must not turn into "overwrite whatever is there". A key file that really
// exists in the target before restore is still refused.
func TestAdminRestore_AbsoluteKeyPaths_NonEmptyKeysDirStillRefused(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", liveTestPassphrase)

	keysDir := t.TempDir()
	srcDir := t.TempDir()
	chdirTest(t, srcDir)
	require.NoError(t, encryption.NewService(absKeyEncCfg(keysDir), srcDir).Initialize(liveTestPassphrase))
	srcDB := filepath.Join(srcDir, "secrets.db")
	configPathFlag = writeAbsKeyPathsConfig(t, srcDir, fmt.Sprintf("  type: local\n  database:\n    path: %s\n", srcDB), keysDir)
	srcCfg, err := loadConfig()
	require.NoError(t, err)
	_, err = storage.NewStorageFactory().CreateStorage(srcCfg)
	require.NoError(t, err)
	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	backupOutput = archivePath
	_, err = captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.NoError(t, err)

	emptyDir(t, keysDir)
	foreign := []byte("someone else's salt")
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "kek.salt"), foreign, 0600))
	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	configPathFlag = writeAbsKeyPathsConfig(t, dstDir, fmt.Sprintf("  type: local\n  database:\n    path: %s\n", filepath.Join(dstDir, "secrets.db")), keysDir)
	restoreInput = archivePath
	restoreOverwriteExisting = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0

	_, err = captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.Error(t, err, "restore must refuse a target keys dir that already holds a non-empty key file")
	got, rerr := os.ReadFile(filepath.Join(keysDir, "kek.salt")) // #nosec G304 -- t.TempDir() path
	require.NoError(t, rerr)
	require.Equal(t, foreign, got, "a refused restore must leave the existing key file untouched")
}

// simulateLiveServer takes what a running keyorix-server holds for its whole
// lifetime: the database's exclusive server lock (serverguard) and the
// exclusive dek.lock flock beside the key files.
func simulateLiveServer(t *testing.T, cfg *config.Config, encCfg *config.EncryptionConfig, baseDir string) {
	t.Helper()
	dbLock, err := serverguard.AcquireExclusive(cfg)
	require.NoError(t, err, "simulated server: database lock")
	t.Cleanup(func() { _ = dbLock.Release() })
	svc := encryption.NewService(encCfg, baseDir)
	require.NoError(t, svc.AcquireExclusiveKeyLock(), "simulated server: dek.lock")
	t.Cleanup(svc.Shutdown)
}

// TestAdminBackup_SQLite_LiveServerRefusedExplicitly: SQLite has no snapshot
// mechanism beside a live writer, so a live backup is refused -- with an
// explicit "stop the server", and no archive.
func TestAdminBackup_SQLite_LiveServerRefusedExplicitly(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", liveTestPassphrase)

	keysDir := t.TempDir()
	srcDir := t.TempDir()
	chdirTest(t, srcDir)
	enc := absKeyEncCfg(keysDir)
	require.NoError(t, encryption.NewService(enc, srcDir).Initialize(liveTestPassphrase))
	configPathFlag = writeAbsKeyPathsConfig(t, srcDir, fmt.Sprintf("  type: local\n  database:\n    path: %s\n", filepath.Join(srcDir, "secrets.db")), keysDir)
	cfg, err := loadConfig()
	require.NoError(t, err)
	_, err = storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	simulateLiveServer(t, cfg, enc, srcDir)

	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	backupOutput = archivePath
	_, err = captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.Error(t, err)
	require.Contains(t, err.Error(), "stop the server first")
	_, statErr := os.Stat(archivePath)
	require.True(t, os.IsNotExist(statErr), "a refused backup must leave no archive")
}

// pgLiveSource sets up a migrated Postgres source with absolute-path keys
// and returns its config, encryption config and keys dir. cwd is srcDir.
func pgLiveSource(t *testing.T) (*config.Config, *config.EncryptionConfig, string, string) {
	t.Helper()
	base := pgAdminTestDSN(t)
	srcDSN := pgAdminIsolatedDatabaseDSN(t, base)
	keysDir := t.TempDir()
	srcDir := t.TempDir()
	chdirTest(t, srcDir)
	enc := absKeyEncCfg(keysDir)
	require.NoError(t, encryption.NewService(enc, srcDir).Initialize(liveTestPassphrase))
	configPathFlag = writeAbsKeyPathsConfig(t, srcDir, fmt.Sprintf("  type: postgres\n  database:\n    dsn: %q\n", srcDSN), keysDir)
	cfg, err := loadConfig()
	require.NoError(t, err)
	_, err = storage.NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)
	seed := pgAdminRawOpen(t, srcDSN)
	require.NoError(t, seed.Create(&models.Project{Name: "live-proj"}).Error)
	return cfg, enc, keysDir, srcDir
}

// TestAdminBackup_Postgres_LiveServer_RoundTrip is #2602: a live backup
// beside a (simulated) running server succeeds and restores.
func TestAdminBackup_Postgres_LiveServer_RoundTrip(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", liveTestPassphrase)

	cfg, enc, keysDir, srcDir := pgLiveSource(t)
	simulateLiveServer(t, cfg, enc, srcDir)

	archivePath := filepath.Join(t.TempDir(), "live.tar.gz")
	backupOutput = archivePath
	backupExclusive = false
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.NoError(t, err, "live backup beside a running server must succeed; output was:\n%s", out)
	require.Contains(t, out, "taking a live backup")
	origKeys := readKeyBytes(t, keysDir)

	// Restore into a fresh database and an empty keys dir (#2604's shape too).
	emptyDir(t, keysDir)
	dstDSN := pgAdminIsolatedDatabaseDSN(t, pgAdminTestDSN(t))
	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	configPathFlag = writeAbsKeyPathsConfig(t, dstDir, fmt.Sprintf("  type: postgres\n  database:\n    dsn: %q\n", dstDSN), keysDir)
	restoreInput = archivePath
	restoreOverwriteExisting = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0
	out, err = captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "output was:\n%s", out)
	require.Equal(t, origKeys, readKeyBytes(t, keysDir))
	var n int64
	require.NoError(t, pgAdminRawOpen(t, dstDSN).Model(&models.Project{}).Where("name = ?", "live-proj").Count(&n).Error)
	require.Equal(t, int64(1), n, "the restored database must contain the source's data")
}

// TestAdminBackup_Postgres_LiveServer_RefusesDuringKeyRotation: a key-file
// rewriter (rotate / rotate-kek / migrate-provider) holding the rewrite lock
// means the key set and the database may be mid-change -- refuse, no archive.
func TestAdminBackup_Postgres_LiveServer_RefusesDuringKeyRotation(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", liveTestPassphrase)

	cfg, enc, keysDir, srcDir := pgLiveSource(t)
	simulateLiveServer(t, cfg, enc, srcDir)
	// What every key-file rewriter holds exclusively for its whole write.
	f, err := os.OpenFile(filepath.Join(keysDir, "data.key.lock"), os.O_CREATE|os.O_RDWR, 0600) // #nosec G304 -- t.TempDir() path
	require.NoError(t, err)
	require.NoError(t, syscall.Flock(int(f.Fd()), syscall.LOCK_EX))
	t.Cleanup(func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() })

	archivePath := filepath.Join(t.TempDir(), "live.tar.gz")
	backupOutput = archivePath
	_, err = captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.Error(t, err)
	require.Contains(t, err.Error(), "key rotation or provider migration is in progress")
	_, statErr := os.Stat(archivePath)
	require.True(t, os.IsNotExist(statErr), "a refused backup must leave no archive")
}

// TestAdminBackup_Postgres_LiveServer_KeyFilesChangedDuringBackup: a key
// file rewritten by a writer that does not take the rewrite lock, between
// the key read and the end of the database read, must fail the backup and
// remove the archive -- never archive keys that may not match the data.
func TestAdminBackup_Postgres_LiveServer_KeyFilesChangedDuringBackup(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", liveTestPassphrase)

	cfg, enc, keysDir, srcDir := pgLiveSource(t)
	simulateLiveServer(t, cfg, enc, srcDir)
	backupLiveAfterReadHook = func() {
		require.NoError(t, os.WriteFile(filepath.Join(keysDir, "kek.salt"), []byte("rewritten mid-backup"), 0600))
	}
	t.Cleanup(func() { backupLiveAfterReadHook = nil })

	archivePath := filepath.Join(t.TempDir(), "live.tar.gz")
	backupOutput = archivePath
	_, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.Error(t, err)
	require.Contains(t, err.Error(), "changed during the backup")
	_, statErr := os.Stat(archivePath)
	require.True(t, os.IsNotExist(statErr), "a backup whose keys changed underneath it must leave no archive")
}

// TestAdminBackup_Postgres_ExclusiveRefusedBesideLiveServer: --exclusive
// needs the database to itself; beside a live server it refuses explicitly
// instead of silently degrading to the snapshot path.
func TestAdminBackup_Postgres_ExclusiveRefusedBesideLiveServer(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv("KEYORIX_MASTER_PASSWORD", liveTestPassphrase)

	cfg, enc, _, srcDir := pgLiveSource(t)
	simulateLiveServer(t, cfg, enc, srcDir)
	origExclusive := backupExclusive
	backupExclusive = true
	t.Cleanup(func() { backupExclusive = origExclusive })

	archivePath := filepath.Join(t.TempDir(), "live.tar.gz")
	backupOutput = archivePath
	_, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.Error(t, err)
	require.Contains(t, err.Error(), "--exclusive needs the database to itself")
	_, statErr := os.Stat(archivePath)
	require.True(t, os.IsNotExist(statErr))
}

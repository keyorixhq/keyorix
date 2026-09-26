// backup_restore_integration_test.go exercises `admin backup` then
// `admin restore` end to end through their real cobra RunE functions (not
// just the archive-parsing helpers backup_restore_test.go covers directly),
// proving the full wiring: a real encrypted local/sqlite deployment backed
// up, restored into a fresh directory with 0600 files, and automatically
// verify-audited (#2099 review item 4).
//
// Not t.Parallel(): mutates package-level cobra flag vars, matching this
// package's existing convention (see fuzz_encryption_command_fault_test.go's
// captureStdout doc comment).
package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
)

// resetBackupRestoreFlags saves and restores every package-level cobra flag
// var this file's tests touch.
func resetBackupRestoreFlags(t *testing.T) {
	t.Helper()
	origBackupOutput := backupOutput
	origInput, origOverwrite, origMaxEntry, origMaxTotal := restoreInput, restoreOverwriteExisting, restoreMaxEntryBytes, restoreMaxTotalBytes
	origCfgPath := configPathFlag
	origForce := forceFlag
	t.Cleanup(func() {
		backupOutput = origBackupOutput
		restoreInput, restoreOverwriteExisting, restoreMaxEntryBytes, restoreMaxTotalBytes = origInput, origOverwrite, origMaxEntry, origMaxTotal
		configPathFlag = origCfgPath
		forceFlag = origForce
	})
}

// writeBackupRestoreTestConfig writes a minimal local/sqlite config file
// pointing at dbPath, with password-provider encryption key material at
// RELATIVE paths "dek.key"/"kek.salt" -- both encryption.Service's on-disk
// writer and keyfiles.Registry (which backup.go/restore.go call with
// baseDir ".") resolve a relative key path against the process's current
// working directory, so the caller must os.Chdir into dir before running
// backup/restore against this config (see chdirTest below).
func writeBackupRestoreTestConfig(t *testing.T, dir, dbPath string) string {
	t.Helper()
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	content := fmt.Sprintf(`storage:
  type: local
  database:
    path: %s
  encryption:
    enabled: true
    dek_path: dek.key
    salt_path: kek.salt
`, dbPath)
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0600))
	return cfgPath
}

// chdirTest os.Chdir's into dir for the remainder of the test, restoring the
// original working directory via t.Cleanup. Safe here because this
// package's tests are not t.Parallel() (see this file's own package doc
// comment) -- os.Chdir is process-global state.
func chdirTest(t *testing.T, dir string) {
	t.Helper()
	orig, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(orig) })
}

func TestAdminBackupRestore_RoundTrip(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())

	srcDir := t.TempDir()
	chdirTest(t, srcDir)

	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	require.NoError(t, encryption.NewService(encCfg, srcDir).Initialize("test-passphrase-1234"))

	srcDBPath := filepath.Join(srcDir, "secrets.db")
	configPathFlag = writeBackupRestoreTestConfig(t, srcDir, srcDBPath)
	srcCfg, err := loadConfig()
	require.NoError(t, err)
	_, err = storage.NewStorageFactory().CreateStorage(srcCfg) // creates + migrates the source DB
	require.NoError(t, err)

	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	backupOutput = archivePath
	require.NoError(t, runAdminBackup(nil, nil))

	dekPath := filepath.Join(srcDir, "dek.key")

	// Restore into a fresh target directory, but the SAME (relative)
	// key-material paths the backup was taken from (restore's own
	// documented precondition). chdirTest below moves the process into
	// dstDir so "dek.key"/"kek.salt" resolve there instead of srcDir --
	// proving restore actually (re)writes them at the new location, not
	// just validates against files still sitting in the old one.
	dstDir := t.TempDir()
	chdirTest(t, dstDir)

	dstDBPath := filepath.Join(dstDir, "secrets.db")
	configPathFlag = writeBackupRestoreTestConfig(t, dstDir, dstDBPath)
	restoreInput = archivePath
	restoreOverwriteExisting = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0

	out, err := captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "output was:\n%s", out)
	require.Contains(t, out, "verify-audit on the restored database: VALID",
		"restore must run verify-audit automatically and report its verdict")

	dstDekPath := filepath.Join(dstDir, "dek.key")
	dstSaltPath := filepath.Join(dstDir, "kek.salt")
	for _, p := range []string{dstDekPath, dstSaltPath, dstDBPath} {
		info, statErr := os.Stat(p)
		require.NoError(t, statErr)
		require.Equal(t, os.FileMode(restoreFileMode), info.Mode().Perm(), "restored %q must always be 0600", p)
	}
	// The restored key material must be BYTE-IDENTICAL to the source, not
	// merely present -- otherwise the restored database would be
	// undecryptable despite every check above passing.
	origDEK, err := os.ReadFile(dekPath)
	require.NoError(t, err)
	gotDEK, err := os.ReadFile(dstDekPath)
	require.NoError(t, err)
	require.Equal(t, origDEK, gotDEK)
}

// TestAdminRestore_FailsOnFormatVersionMismatch is a light sanity check that
// restore's format-version guard still runs after the readBackupArchive
// rewrite -- a regression here would mean an old backup silently
// misinterpreted under a newer/older binary instead of refused outright.
func TestAdminRestore_FailsOnFormatVersionMismatch(t *testing.T) {
	resetBackupRestoreFlags(t)

	dbData := []byte("db")
	manifest := buildTestManifest(dbData, nil)
	manifest.FormatVersion = backupFormatVersion + 1

	dir := t.TempDir()
	archivePath := filepath.Join(dir, "backup.tar.gz")
	require.NoError(t, writeBackupArchive(archivePath, manifest, dbData, nil))

	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	configPathFlag = writeBackupRestoreTestConfig(t, dstDir, filepath.Join(dstDir, "secrets.db"))
	restoreInput = archivePath
	restoreOverwriteExisting = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0

	err := runAdminRestore(nil, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "format version")
}

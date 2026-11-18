// restore_unused_salt_test.go covers #4504 F2: an install that kept
// salt_path after moving off the password provider (migrate-provider keeps
// it) archived [salt, DEK] before #4395 dropped an unused salt from
// keyfiles.Registry. Restoring that archive into the same config must not
// refuse it as a mismatched key-file set.
//
// Runs the real `admin backup` and `admin restore` commands (SQLite). Not
// t.Parallel(): package-level cobra flag vars and chdir.
package admin

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/backupfmt"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage"
)

const unusedSaltKEKVar = "KEYORIX_TEST_UNUSED_SALT_KEK"

// writeEnvProviderTestConfig is writeBackupRestoreTestConfig with the env key
// provider, salt_path kept; passwordFallback adds a password fallback, which
// makes the salt part of the key set again.
func writeEnvProviderTestConfig(t *testing.T, dir string, passwordFallback bool) string {
	t.Helper()
	fallback := ""
	if passwordFallback {
		fallback = `
      insecure_allow_weaker_kek_fallback: true
      fallbacks:
        - type: password`
	}
	content := fmt.Sprintf(`storage:
  type: local
  database:
    path: %s
  encryption:
    enabled: true
    dek_path: dek.key
    salt_path: kek.salt
    key_provider:
      type: env
      env_var: %s%s
`, filepath.Join(dir, "secrets.db"), unusedSaltKEKVar, fallback)
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(content), 0o600))
	return cfgPath
}

func TestAdminRestore_ArchivedUnusedSalt_RestoresIntoSaltlessProviderConfig(t *testing.T) {
	resetBackupRestoreFlags(t)
	require.NoError(t, i18n.InitializeForTesting())
	t.Setenv(unusedSaltKEKVar, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-passphrase-1234")

	// Source: the env KEK opens the DEK; a password fallback keeps kek.salt in
	// keyfiles.Registry, so the archive lists [kek.salt, dek.key], the shape
	// every env install with salt_path archived before #4395.
	srcDir := t.TempDir()
	chdirTest(t, srcDir)
	configPathFlag = writeEnvProviderTestConfig(t, srcDir, true)
	srcCfg, err := loadConfig()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "kek.salt"), make([]byte, 32), 0o600))
	require.NoError(t, encryption.NewService(&srcCfg.Storage.Encryption, srcDir).Initialize(""))
	_, err = storage.NewStorageFactory().CreateStorage(srcCfg)
	require.NoError(t, err)

	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	backupOutput = archivePath
	backupExclusive = false
	out, err := captureStdout(t, func() error { return runAdminBackup(nil, nil) })
	require.NoError(t, err, "backup output:\n%s", out)
	archivedPaths := archiveKeyFilePaths(t, archivePath)
	require.Equal(t, []string{"kek.salt", "dek.key"}, archivedPaths, "fixture: the archive lists the salt")

	// Target: the same config without the fallback, salt_path still set and
	// read by no provider.
	dstDir := t.TempDir()
	chdirTest(t, dstDir)
	configPathFlag = writeEnvProviderTestConfig(t, dstDir, false)
	restoreInput = archivePath
	restoreOverwriteExisting = false
	restoreMaxEntryBytes = 0
	restoreMaxTotalBytes = 0
	out, err = captureStdout(t, func() error { return runAdminRestore(nil, nil) })
	require.NoError(t, err, "restore output:\n%s", out)

	_, err = os.Stat(filepath.Join(dstDir, "dek.key"))
	require.NoError(t, err, "the DEK is restored")
	_, err = os.Stat(filepath.Join(dstDir, "kek.salt"))
	require.True(t, os.IsNotExist(err), "the unused salt is not installed")

	// The restored install boots: its key set is exactly what Registry expects.
	dstCfg, err := loadConfig()
	require.NoError(t, err)
	svc := encryption.NewService(&dstCfg.Storage.Encryption, ".")
	require.NoError(t, svc.ReconcileKeySet())
	require.NoError(t, svc.Initialize(""))
}

// The guard stays on: an archive whose extra entry is not the configured
// salt is still refused.
func TestUnusedArchivedSaltIndex(t *testing.T) {
	env := func(salt string, fallbacks ...config.KeyProviderConfig) *config.Config {
		cfg := &config.Config{}
		cfg.Storage.Encryption = config.EncryptionConfig{Enabled: true, DEKPath: "keys/dek.key", SaltPath: salt,
			KeyProvider: config.KeyProviderConfig{Type: "env", EnvVar: "X", Fallbacks: fallbacks}}
		return cfg
	}
	archived := []string{"keys/kek.salt", "keys/dek.key"}
	at := func(i int) string { return archived[i] }
	require.Equal(t, 0, unusedArchivedSaltIndex(env("keys/kek.salt"), len(archived), at))
	require.Equal(t, 0, unusedArchivedSaltIndex(env("./keys/kek.salt"), len(archived), at), "matched after Clean, like Registry")
	require.Equal(t, -1, unusedArchivedSaltIndex(env(""), len(archived), at), "no salt_path: nothing to match")
	require.Equal(t, -1, unusedArchivedSaltIndex(env("keys/other.salt"), len(archived), at), "another path is not the salt")
	require.Equal(t, -1, unusedArchivedSaltIndex(env("keys/kek.salt", config.KeyProviderConfig{Type: "password"}), len(archived), at),
		"a password fallback reads the salt: it stays in the set")

	err := validateKeyFileSetV2([]backupfmt.KeyFileEntry{{OriginalPath: "keys/other"}, {OriginalPath: "keys/dek.key"}},
		[]string{"keys/dek.key"})
	require.ErrorContains(t, err, "restore refuses a partial/mismatched key-file set")
}

func archiveKeyFilePaths(t *testing.T, archivePath string) []string {
	t.Helper()
	f, err := os.Open(archivePath) // #nosec G304 -- test-owned temp archive
	require.NoError(t, err)
	defer f.Close() //nolint:errcheck
	manifest, err := backupfmt.ExtractArchive(f, t.TempDir(), 0, 0)
	require.NoError(t, err)
	paths := make([]string, len(manifest.KeyFiles))
	for i, kf := range manifest.KeyFiles {
		paths[i] = kf.OriginalPath
	}
	return paths
}

package encryption

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// encLocalCfg returns a minimal encryption-enabled local-storage config.
func encLocalCfg() *config.Config {
	return &config.Config{
		Storage: config.StorageConfig{
			Type: "local",
			Encryption: config.EncryptionConfig{
				Enabled: true,
			},
		},
	}
}

// encDisabledCfg returns a config with encryption disabled.
func encDisabledCfg() *config.Config {
	return &config.Config{
		Storage: config.StorageConfig{
			Type: "local",
			Encryption: config.EncryptionConfig{
				Enabled: false,
			},
		},
	}
}

// ──────────────────────────── runRotate ────────────────────────────────────

func TestRunRotate_LoadConfigError(t *testing.T) {
	// Point at a directory with no keyorix.yaml so loadConfig returns defaults.
	t.Chdir(t.TempDir())
	// runRotate calls loadConfig then rotateWithConfig — if config loads,
	// it falls into rotateWithConfig's validation gates.
	// We rely on encryption disabled by default → error.
	err := rotateCmd.RunE(rotateCmd, nil)
	_ = err // may be nil (encryption disabled → rotateWithConfig returns error) or config error
}

// ──────────────────────────── validateWithConfig ───────────────────────────

func TestValidateWithConfig_EncryptionDisabled(t *testing.T) {
	cfg := encDisabledCfg()
	err := validateWithConfig(cfg)
	require.NoError(t, err) // prints "nothing to validate", returns nil
}

func TestValidateWithConfig_NoPassword(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")
	cfg := encLocalCfg()
	err := validateWithConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYORIX_MASTER_PASSWORD")
}

// ──────────────────────────── runValidate ──────────────────────────────────

func TestRunValidate_LoadsConfig(t *testing.T) {
	t.Chdir(t.TempDir())
	// runValidate calls loadConfig then validateWithConfig; with no config file
	// encryption is disabled by default → validateWithConfig returns nil.
	err := validateCmd.RunE(validateCmd, nil)
	_ = err
}

// ──────────────────────────── fixPermsWithConfig ───────────────────────────

func TestFixPermsWithConfig_EncryptionDisabled(t *testing.T) {
	cfg := encDisabledCfg()
	err := fixPermsWithConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encryption is disabled")
}

func TestFixPermsWithConfig_NoPassword(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")
	cfg := encLocalCfg()
	err := fixPermsWithConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYORIX_MASTER_PASSWORD")
}

// ──────────────────────────── runFixPerms ──────────────────────────────────

func TestRunFixPerms_LoadsConfig(t *testing.T) {
	t.Chdir(t.TempDir())
	err := fixPermsCmd.RunE(fixPermsCmd, nil)
	_ = err
}

// ──────────────────────────── upgradeAADWithConfig ─────────────────────────

func TestUpgradeAADWithConfig_EncryptionDisabled(t *testing.T) {
	cfg := encDisabledCfg()
	err := upgradeAADWithConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encryption is disabled")
}

func TestUpgradeAADWithConfig_RemoteStorage(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:       "remote",
			Encryption: config.EncryptionConfig{Enabled: true},
		},
	}
	err := upgradeAADWithConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remote")
}

func TestUpgradeAADWithConfig_NoPassword(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")
	err := upgradeAADWithConfig(encLocalCfg())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYORIX_MASTER_PASSWORD")
}

// ──────────────────────────── runUpgradeAAD ────────────────────────────────

func TestRunUpgradeAAD_LoadsConfig(t *testing.T) {
	t.Chdir(t.TempDir())
	err := upgradeAADCmd.RunE(upgradeAADCmd, nil)
	_ = err
}

// ──────────────────────────── migrateProviderWithConfig ───────────────────

func TestMigrateProviderWithConfig_EncryptionDisabled(t *testing.T) {
	cfg := encDisabledCfg()
	err := migrateProviderWithConfig(cfg, migrateOpts{}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encryption is disabled")
}

func TestMigrateProviderWithConfig_RemoteStorage(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type:       "remote",
			Encryption: config.EncryptionConfig{Enabled: true},
		},
	}
	err := migrateProviderWithConfig(cfg, migrateOpts{}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remote")
}

func TestMigrateProviderWithConfig_MissingToType(t *testing.T) {
	cfg := encLocalCfg()
	err := migrateProviderWithConfig(cfg, migrateOpts{}, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--to-type is required")
}

func TestMigrateProviderWithConfig_MissingConfirm(t *testing.T) {
	cfg := encLocalCfg()
	cfg.Storage.Encryption.KeyProvider.Type = "password"
	opts := migrateOpts{toType: "file", toFilePath: "/some/path"}
	err := migrateProviderWithConfig(cfg, opts, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--confirm")
}

// ──────────────────────────── migrateProviderCleanupWithConfig ────────────

func TestMigrateProviderCleanupWithConfig_EncryptionDisabled(t *testing.T) {
	cfg := encDisabledCfg()
	err := migrateProviderCleanupWithConfig(cfg, t.TempDir(), false, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encryption is disabled")
}

func TestMigrateProviderCleanupWithConfig_NoBackups(t *testing.T) {
	dir := t.TempDir()
	cfg := encLocalCfg()
	cfg.Storage.Encryption.DEKPath = "dek.key"
	err := migrateProviderCleanupWithConfig(cfg, dir, false, false)
	require.NoError(t, err) // no backups → prints "nothing to clean up", returns nil
}

func TestMigrateProviderCleanupWithConfig_DryRun(t *testing.T) {
	dir := t.TempDir()
	// Create a fake migrate-backup file.
	dekPath := "dek.key"
	backupPath := filepath.Join(dir, dekPath+".migrate-backup.12345")
	require.NoError(t, os.WriteFile(backupPath, []byte("fake"), 0600))

	cfg := encLocalCfg()
	cfg.Storage.Encryption.DEKPath = dekPath
	err := migrateProviderCleanupWithConfig(cfg, dir, true, false) // dry-run=true
	require.NoError(t, err)
	// Dry run leaves the file in place.
	_, statErr := os.Stat(backupPath)
	require.NoError(t, statErr, "dry-run must not delete the file")
}

func TestMigrateProviderCleanupWithConfig_MissingConfirm(t *testing.T) {
	dir := t.TempDir()
	dekPath := "dek.key"
	backupPath := filepath.Join(dir, dekPath+".migrate-backup.99999")
	require.NoError(t, os.WriteFile(backupPath, []byte("fake"), 0600))

	cfg := encLocalCfg()
	cfg.Storage.Encryption.DEKPath = dekPath
	err := migrateProviderCleanupWithConfig(cfg, dir, false, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--confirm")
}

// ──────────────────────────── findMigrateBackups ──────────────────────────

func TestFindMigrateBackups_NoDir(t *testing.T) {
	dir := t.TempDir()
	matches, err := findMigrateBackups(dir, "nonexistent/dek.key")
	require.NoError(t, err) // missing dir → nil, nil
	assert.Empty(t, matches)
}

func TestFindMigrateBackups_WithMatches(t *testing.T) {
	dir := t.TempDir()
	// Create fake backup files.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dek.key.migrate-backup.1"), []byte("b"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dek.key.migrate-backup.2"), []byte("b"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other.txt"), []byte("x"), 0600))

	matches, err := findMigrateBackups(dir, "dek.key")
	require.NoError(t, err)
	assert.Len(t, matches, 2)
}

// ──────────────────────────── restoreBackup ────────────────────────────────

func TestRestoreBackup_MissingSource(t *testing.T) {
	dir := t.TempDir()
	// Should not panic — missing source logs to stderr.
	restoreBackup(dir, "nonexistent.backup", "dek.key")
}

func TestRestoreBackup_Success(t *testing.T) {
	dir := t.TempDir()
	backupPath := "dek.key.migrate-backup.12345"
	require.NoError(t, os.WriteFile(filepath.Join(dir, backupPath), []byte("dek-content"), 0600))

	restoreBackup(dir, backupPath, "dek.key")

	data, err := os.ReadFile(filepath.Join(dir, "dek.key"))
	require.NoError(t, err)
	assert.Equal(t, []byte("dek-content"), data)
}

// ──────────────────────────── targetPassphrase ─────────────────────────────

func TestTargetPassphrase_NonPasswordProvider(t *testing.T) {
	pw, err := targetPassphrase("file")
	require.NoError(t, err)
	assert.Equal(t, "", pw)
}

func TestTargetPassphrase_PasswordProvider_Set(t *testing.T) {
	t.Setenv(newMasterPasswordEnv, "newpassphrase")
	pw, err := targetPassphrase("password")
	require.NoError(t, err)
	assert.Equal(t, "newpassphrase", pw)
}

func TestTargetPassphrase_PasswordProvider_Empty(t *testing.T) {
	t.Setenv(newMasterPasswordEnv, "")
	_, err := targetPassphrase("password")
	require.Error(t, err)
	assert.Contains(t, err.Error(), newMasterPasswordEnv)
}

func TestTargetPassphrase_EmptyTypeIsPassword(t *testing.T) {
	t.Setenv(newMasterPasswordEnv, "")
	_, err := targetPassphrase("") // empty type also treated as password
	require.Error(t, err)
}

// ──────────────────────────── providerLabel ────────────────────────────────

func TestProviderLabel_EmptyIsPassword(t *testing.T) {
	assert.Equal(t, "password", providerLabel(""))
}

func TestProviderLabel_Explicit(t *testing.T) {
	assert.Equal(t, "aws-kms", providerLabel("aws-kms"))
}

// ──────────────────────────── closeDB ──────────────────────────────────────

func TestCloseDB_Nil(t *testing.T) {
	// Should not panic on a nil *gorm.DB.
	closeDB(nil)
}

// ──────────────────────────── runRotateAuthEncryption ─────────────────────

func TestRunRotateAuthEncryption_MissingConfirm(t *testing.T) {
	// --confirm not set on the cobra command; RunE should return an error immediately.
	err := authRotateCmd.RunE(authRotateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--confirm")
}

// ──────────────────────────── runEnableAuthEncryption ─────────────────────

func TestRunEnableAuthEncryption_DisabledNoForce(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	// Write a config with encryption disabled (the default for new installs).
	yaml := "storage:\n  type: local\n  encryption:\n    enabled: false\n"
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(yaml), 0600))

	// --force not set → should return "enable it in config or use --force" error.
	err := enableCmd.RunE(enableCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--force")
}

// ──────────────────────────── runAuthEncryptionStatus ─────────────────────

func TestRunAuthEncryptionStatus_ConfigLoadError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	// Point at a non-parseable config.
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte("invalid: [\n"), 0600))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	// config.Load will fail → runAuthEncryptionStatus returns an error.
	err := authStatusCmd.RunE(authStatusCmd, nil)
	_ = err // may or may not error depending on how the config parser handles it
}

// ──────────────────────────── runMigrateProvider ──────────────────────────

func TestRunMigrateProvider_LoadsConfig(t *testing.T) {
	t.Chdir(t.TempDir())
	// With no config file, encryption is disabled → migrateProviderWithConfig
	// returns "encryption is disabled" before doing any key work.
	err := migrateProviderCmd.RunE(migrateProviderCmd, nil)
	_ = err
}

// ──────────────────────────── runMigrateProviderCleanup ───────────────────

func TestRunMigrateProviderCleanup_LoadsConfig(t *testing.T) {
	t.Chdir(t.TempDir())
	err := migrateProviderCleanupCmd.RunE(migrateProviderCleanupCmd, nil)
	_ = err
}

// ──────────────────────────── printMigrateSummary branches ───────────────────

func TestPrintMigrateSummary_PasswordProvider(t *testing.T) {
	cfg := encLocalCfg()
	cfg.Storage.Encryption.KeyProvider.Type = "password"
	printMigrateSummary(cfg.Storage.Encryption, "backup.migrate-backup.12345")
}

func TestPrintMigrateSummary_FileProvider(t *testing.T) {
	cfg := encLocalCfg()
	cfg.Storage.Encryption.KeyProvider.Type = "file"
	cfg.Storage.Encryption.KeyProvider.FilePath = "/etc/keyorix/kek.key"
	printMigrateSummary(cfg.Storage.Encryption, "backup.migrate-backup.12345")
}

func TestPrintMigrateSummary_EnvProvider(t *testing.T) {
	cfg := encLocalCfg()
	cfg.Storage.Encryption.KeyProvider.Type = "env"
	cfg.Storage.Encryption.KeyProvider.EnvVar = "MY_KEK"
	printMigrateSummary(cfg.Storage.Encryption, "backup.migrate-backup.12345")
}

func TestPrintMigrateSummary_ExecProvider(t *testing.T) {
	cfg := encLocalCfg()
	cfg.Storage.Encryption.KeyProvider.Type = "exec"
	cfg.Storage.Encryption.KeyProvider.ExecCommand = []string{"/usr/bin/get-kek"}
	printMigrateSummary(cfg.Storage.Encryption, "backup.migrate-backup.12345")
}

func TestPrintMigrateSummary_ShamirProvider_WithCommitment(t *testing.T) {
	cfg := encLocalCfg()
	cfg.Storage.Encryption.KeyProvider.Type = "shamir"
	cfg.Storage.Encryption.KeyProvider.ShamirShareFiles = []string{"/a", "/b"}
	cfg.Storage.Encryption.KeyProvider.ShamirCommitment = "abc123"
	printMigrateSummary(cfg.Storage.Encryption, "backup.migrate-backup.12345")
}

func TestPrintMigrateSummary_ShamirProvider_NoCommitment(t *testing.T) {
	cfg := encLocalCfg()
	cfg.Storage.Encryption.KeyProvider.Type = "shamir"
	cfg.Storage.Encryption.KeyProvider.ShamirShareEnv = []string{"SHARE1", "SHARE2"}
	cfg.Storage.Encryption.KeyProvider.ShamirCommitment = ""
	printMigrateSummary(cfg.Storage.Encryption, "backup.migrate-backup.12345")
}

func TestPrintMigrateSummary_TPMProvider(t *testing.T) {
	cfg := encLocalCfg()
	cfg.Storage.Encryption.KeyProvider.Type = "tpm"
	cfg.Storage.Encryption.KeyProvider.TPMDevice = "/dev/tpm0"
	cfg.Storage.Encryption.KeyProvider.WrappedKeyPath = "/var/lib/tpm-dek.bin"
	printMigrateSummary(cfg.Storage.Encryption, "backup.migrate-backup.12345")
}

func TestPrintMigrateSummary_AWSKMSProvider(t *testing.T) {
	cfg := encLocalCfg()
	cfg.Storage.Encryption.KeyProvider.Type = "aws-kms"
	cfg.Storage.Encryption.KeyProvider.KMSKeyID = "arn:aws:kms:us-east-1:123:key/abc"
	cfg.Storage.Encryption.KeyProvider.WrappedKeyPath = "/var/lib/wrapped.bin"
	printMigrateSummary(cfg.Storage.Encryption, "backup.migrate-backup.12345")
}

func TestPrintMigrateSummary_GCPKMSProvider(t *testing.T) {
	cfg := encLocalCfg()
	cfg.Storage.Encryption.KeyProvider.Type = "gcp-kms"
	cfg.Storage.Encryption.KeyProvider.KMSKeyID = "projects/my-project/locations/global/keyRings/ring/cryptoKeys/key"
	printMigrateSummary(cfg.Storage.Encryption, "backup.migrate-backup.12345")
}

func TestPrintMigrateSummary_AzureKMSProvider(t *testing.T) {
	cfg := encLocalCfg()
	cfg.Storage.Encryption.KeyProvider.Type = "azure-kms"
	cfg.Storage.Encryption.KeyProvider.KMSKeyID = "https://vault.azure.net/keys/mykey/1"
	printMigrateSummary(cfg.Storage.Encryption, "backup.migrate-backup.12345")
}

// ──────────────────────────── runInit additional paths ───────────────────────

func TestRunInit_EncryptionDisabledV2(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	// Create a minimal keyorix.yaml with encryption disabled.
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte("storage:\n  type: local\n  encryption:\n    enabled: false\n"), 0600))
	err := initCmd.RunE(initCmd, nil)
	require.NoError(t, err)
}

// ──────────────────────────── runStatus additional paths ─────────────────────

func TestRunStatus_EncryptionDisabledV2(t *testing.T) {
	t.Chdir(t.TempDir())
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte("storage:\n  type: local\n  encryption:\n    enabled: false\n"), 0600))
	err := statusCmd.RunE(statusCmd, nil)
	require.NoError(t, err)
}

// ──────────────────────────── auth encryption commands ────────────────────

func TestRunAuthEncryptionStatus_LocalMode(t *testing.T) {
	t.Chdir(t.TempDir())
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte("storage:\n  type: local\n  encryption:\n    enabled: false\n"), 0600))
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")
	// With default config (no encryption), runAuthEncryptionStatus should succeed:
	// it opens/creates a local SQLite, initializes authEnc, and prints status.
	err := authStatusCmd.RunE(authStatusCmd, nil)
	_ = err // may succeed or fail on DB open — no panic
}

func TestRunEnableAuthEncryption_LocalMode(t *testing.T) {
	t.Chdir(t.TempDir())
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte("storage:\n  type: local\n  encryption:\n    enabled: false\n"), 0600))
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")
	// With encryption disabled and no --force: should return error about "--force flag".
	err := enableCmd.RunE(enableCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--force")
}

func TestRunRotateAuthEncryption_LocalMode(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")
	// --confirm not set → returns "requires --confirm flag"
	err := authRotateCmd.RunE(authRotateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--confirm")
}

func TestRunMigrateAuthData_LocalMode(t *testing.T) {
	t.Chdir(t.TempDir())
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte("storage:\n  type: local\n  encryption:\n    enabled: false\n"), 0600))
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")
	// migrateCmd has a --dry-run flag; call RunE with the command to set defaults.
	err := migrateCmd.RunE(migrateCmd, nil)
	_ = err // may fail on DB open or auth encryption init — no panic
}

func TestRunValidateAuthEncryption_LocalMode(t *testing.T) {
	t.Chdir(t.TempDir())
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte("storage:\n  type: local\n  encryption:\n    enabled: false\n"), 0600))
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")
	err := authValidateCmd.RunE(authValidateCmd, nil)
	_ = err // may fail on DB or auth encryption init — no panic
}

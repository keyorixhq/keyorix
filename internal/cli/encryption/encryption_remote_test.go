package encryption

import (
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func encryptionEnabledLocalCfg() *config.Config {
	return &config.Config{
		Storage: config.StorageConfig{
			Type: "local",
			Encryption: config.EncryptionConfig{
				Enabled: true,
			},
		},
	}
}

// TestRotateWithConfig_DryRunSkipsConfirm verifies that --dry-run does not
// require --confirm (it returns a different error about missing env/key, not
// about --confirm).
func TestRotateWithConfig_DryRunSkipsConfirmGate(t *testing.T) {
	cfg := encryptionEnabledLocalCfg()
	// dry-run=true skips the --confirm gate; it will then fail on key init
	// (no KEYORIX_MASTER_PASSWORD / no real key files) — but NOT on --confirm.
	err := rotateWithConfig(cfg, false, true)
	if err != nil {
		assert.NotContains(t, err.Error(), "--confirm",
			"dry-run should not require --confirm; got: %v", err)
	}
}

// TestMasterPassphrase_PasswordProviderRequiresEnvVar verifies the default
// (password) provider path of masterPassphrase.
func TestMasterPassphrase_PasswordProviderRequiresEnvVar(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Encryption: config.EncryptionConfig{
				Enabled: true,
				// KeyProvider.Type is zero-value "" → treated as "password".
			},
		},
	}
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")
	_, err := masterPassphrase(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYORIX_MASTER_PASSWORD")
}

func TestMasterPassphrase_PasswordProviderReturnsValue(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Encryption: config.EncryptionConfig{
				Enabled: true,
			},
		},
	}
	t.Setenv("KEYORIX_MASTER_PASSWORD", "supersecret")
	pw, err := masterPassphrase(cfg)
	require.NoError(t, err)
	assert.Equal(t, "supersecret", pw)
}

func TestMasterPassphrase_NonPasswordProviderReturnsEmpty(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Encryption: config.EncryptionConfig{
				Enabled: true,
				KeyProvider: config.KeyProviderConfig{
					Type: "file",
				},
			},
		},
	}
	// Should return ("", nil) without reading KEYORIX_MASTER_PASSWORD.
	t.Setenv("KEYORIX_MASTER_PASSWORD", "should-not-be-used")
	pw, err := masterPassphrase(cfg)
	require.NoError(t, err)
	assert.Equal(t, "", pw)
}

func TestEncryptionCmdStructure(t *testing.T) {
	names := make(map[string]bool)
	for _, c := range EncryptionCmd.Commands() {
		names[c.Name()] = true
	}
	for _, expected := range []string{"init", "status", "rotate", "upgrade-aad", "validate", "fix-perms"} {
		assert.True(t, names[expected], "expected subcommand %q to be registered", expected)
	}
}

func TestRotateCmd_HasExpectedFlags(t *testing.T) {
	for _, f := range []string{"confirm", "dry-run"} {
		assert.NotNil(t, rotateCmd.Flags().Lookup(f), "rotate should have --%s flag", f)
	}
}

// TestRunInit_EncryptionDisabled verifies that `encryption init` exits cleanly
// (without error) when encryption is disabled in config — it only prints a message.
func TestRunInit_EncryptionDisabled(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	// Write a config with encryption disabled.
	yaml := "storage:\n  type: local\n  encryption:\n    enabled: false\n"
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(yaml), 0600))

	err := initCmd.RunE(initCmd, nil)
	require.NoError(t, err)
}

// TestRunStatus_EncryptionDisabled verifies that `encryption status` exits
// cleanly when encryption is disabled.
func TestRunStatus_EncryptionDisabled(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	yaml := "storage:\n  type: local\n  encryption:\n    enabled: false\n"
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(yaml), 0600))

	err := statusCmd.RunE(statusCmd, nil)
	require.NoError(t, err)
}

// TestRunStatus_EncryptionEnabled_NoPassword verifies that `encryption status`
// with encryption enabled returns nil (it logs the error, does not propagate it).
func TestRunStatus_EncryptionEnabled_NoPassword(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")

	yaml := "storage:\n  type: local\n  encryption:\n    enabled: true\n    dek_path: ./dek.key\n    salt_path: ./salt.bin\n"
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(yaml), 0600))

	// runStatus with encryption enabled but no password logs a warning and returns nil.
	err := statusCmd.RunE(statusCmd, nil)
	require.NoError(t, err)
}

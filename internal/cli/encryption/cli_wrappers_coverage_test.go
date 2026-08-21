// cli_wrappers_coverage_test.go — coverage uplift for the thin cobra RunE
// wrappers in encryption.go that were previously only exercised through their
// config.Load/loadConfig ERROR branch:
//
//   - runInit / runStatus: the initLocalKeyOpService failure branch (a live
//     server or in-progress rotation holds the exclusive key lock), reached
//     via the real cobra command with a real config file.
//   - runRotate / runUpgradeAAD / runValidate / runFixPerms: the "delegate to
//     the *WithConfig testable core" line itself, reached by giving loadConfig
//     a real, loadable config (via KEYORIX_CONFIG_PATH) instead of letting it
//     fail first.
package encryption

import (
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	enc "github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeEncEnabledConfigYAML writes a keyorix.yaml with local storage and
// encryption enabled at the given key paths, and returns its absolute path
// for KEYORIX_CONFIG_PATH.
func writeEncEnabledConfigYAML(t *testing.T, dekPath, saltPath string) string {
	t.Helper()
	yaml := fmt.Sprintf(`
storage:
  type: local
  encryption:
    enabled: true
    dek_path: %s
    salt_path: %s
`, dekPath, saltPath)
	return writeConfig(t, yaml)
}

// ── runInit / runStatus: initLocalKeyOpService refusal while a live server ──
// ── (or in-progress rotation/migrate-provider) holds the exclusive lock ─────

func TestRunInit_RefusedWhileServerHoldsLock(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	const pass = "cli-wrapper-lock-init-passphrase"
	t.Setenv("KEYORIX_MASTER_PASSWORD", pass)

	cfgPath := writeEncEnabledConfigYAML(t, "dek.key", "kek.salt")
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}

	// Provision key material up front (mirrors a prior `keyorix encryption init`).
	setup := enc.NewService(encCfg, workDir)
	require.NoError(t, setup.Initialize(pass))
	setup.Shutdown()

	// Simulate a live server (or an in-progress rotation/migrate-provider)
	// holding the key directory exclusively.
	serverSvc := enc.NewService(encCfg, workDir)
	require.NoError(t, serverSvc.Initialize(pass))
	require.NoError(t, serverSvc.AcquireExclusiveKeyLock())
	defer serverSvc.Shutdown()

	err := initCmd.RunE(initCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "a live server or an in-progress rotation")
}

func TestRunStatus_PrintsErrorWhileServerHoldsLock(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	const pass = "cli-wrapper-lock-status-passphrase"
	t.Setenv("KEYORIX_MASTER_PASSWORD", pass)

	cfgPath := writeEncEnabledConfigYAML(t, "dek.key", "kek.salt")
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	encCfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}

	setup := enc.NewService(encCfg, workDir)
	require.NoError(t, setup.Initialize(pass))
	setup.Shutdown()

	serverSvc := enc.NewService(encCfg, workDir)
	require.NoError(t, serverSvc.Initialize(pass))
	require.NoError(t, serverSvc.AcquireExclusiveKeyLock())
	defer serverSvc.Shutdown()

	// runStatus does NOT return the initLocalKeyOpService error — it prints
	// "❌ <err>" and returns nil, so assert on the printed message instead.
	out := captureProviderStatusOutput(t, func() {
		err := statusCmd.RunE(statusCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "a live server or an in-progress rotation")
}

// ── runRotate / runUpgradeAAD / runValidate / runFixPerms: reach the ────────
// ── delegate-to-*WithConfig line by giving loadConfig a real, loadable ──────
// ── config instead of letting config.Load fail first. ───────────────────────

func TestRunRotate_DelegatesToRotateWithConfig_DisabledEncryption(t *testing.T) {
	cfgPath := writeMinimalConfig(t) // local storage, encryption disabled
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	err := rotateCmd.RunE(rotateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encryption is disabled")
}

func TestRunUpgradeAAD_DelegatesToUpgradeAADWithConfig_DisabledEncryption(t *testing.T) {
	cfgPath := writeMinimalConfig(t)
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	err := upgradeAADCmd.RunE(upgradeAADCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encryption is disabled")
}

func TestRunValidate_DelegatesToValidateWithConfig_DisabledEncryption(t *testing.T) {
	cfgPath := writeMinimalConfig(t)
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	// validateWithConfig treats disabled encryption as "nothing to validate"
	// and returns nil — assert on the printed message to confirm the delegate
	// call (and its early-return branch) actually ran.
	out := captureProviderStatusOutput(t, func() {
		err := validateCmd.RunE(validateCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "nothing to validate")
}

func TestRunFixPerms_DelegatesToFixPermsWithConfig_DisabledEncryption(t *testing.T) {
	cfgPath := writeMinimalConfig(t)
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	err := fixPermsCmd.RunE(fixPermsCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encryption is disabled")
}

// cli_encryption_s17_test.go — coverage uplift for:
//   - internal/cli/encryption/auth_encryption_validate.go:19 runValidateAuthEncryption (38.2%)
//   - internal/cli/encryption/auth_encryption_migrate.go:17 runMigrateAuthData (50%)
//   - internal/cli/encryption/migrate_provider.go:130 runMigrateProviderCleanup (60%)
//   - internal/cli/encryption/migrate_provider.go:217 runMigrateProvider (60%)
//
// All four are thin cobra shims. We test:
//  1. The config-load error path (no keyorix.yaml in cwd → config.Load fails).
//  2. The success-delegate path by pointing KEYORIX_CONFIG_PATH at a minimal
//     temp YAML that loads cleanly, then letting the shim reach the testable
//     core which fires an early-exit guard (encryption disabled, missing
//     --to-type, or --confirm gate) before any key or DB work.
package encryption

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── runValidateAuthEncryption ────────────────────────────────────────────────

// TestRunValidateAuthEncryption_ConfigLoadError verifies the first error branch
// of runValidateAuthEncryption: config.Load("") fails when there is no
// keyorix.yaml in the working directory, and the error is wrapped with
// "failed to load config".
func TestRunValidateAuthEncryption_ConfigLoadError(t *testing.T) {
	t.Chdir(t.TempDir()) // no keyorix.yaml → config.Load("") returns an error
	t.Setenv("KEYORIX_CONFIG_PATH", "")

	err := authValidateCmd.RunE(authValidateCmd, nil)
	if err == nil {
		t.Fatal("expected config-load error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to load config") {
		t.Errorf("expected 'failed to load config' in error, got: %v", err)
	}
}

// TestRunValidateAuthEncryption_DBOpenError drives the second error branch of
// runValidateAuthEncryption: config.Load succeeds but openDatabase fails
// because the storage type is unsupported. The error is wrapped with
// "failed to open database".
func TestRunValidateAuthEncryption_DBOpenError(t *testing.T) {
	t.Chdir(t.TempDir())
	cfgPath := writeConfig(t, badStorageConfigYAML)
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	err := authValidateCmd.RunE(authValidateCmd, nil)
	if err == nil {
		t.Fatal("expected database-open error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to open database") {
		t.Errorf("expected 'failed to open database' in error, got: %v", err)
	}
}

// ── runMigrateAuthData ───────────────────────────────────────────────────────

// TestRunMigrateAuthData_ConfigLoadError verifies the first error branch of
// runMigrateAuthData: same config-load failure as above.
func TestRunMigrateAuthData_ConfigLoadError(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_CONFIG_PATH", "")

	err := migrateCmd.RunE(migrateCmd, nil)
	if err == nil {
		t.Fatal("expected config-load error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to load config") {
		t.Errorf("expected 'failed to load config' in error, got: %v", err)
	}
}

// TestRunMigrateAuthData_DBOpenError drives the second error branch of
// runMigrateAuthData: config.Load succeeds but openDatabase fails because the
// storage type is unsupported. The error is wrapped with "failed to open
// database".
func TestRunMigrateAuthData_DBOpenError(t *testing.T) {
	t.Chdir(t.TempDir())
	cfgPath := writeConfig(t, badStorageConfigYAML)
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	err := migrateCmd.RunE(migrateCmd, nil)
	if err == nil {
		t.Fatal("expected database-open error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to open database") {
		t.Errorf("expected 'failed to open database' in error, got: %v", err)
	}
}

// minimalConfigYAML is a YAML snippet for a local config with encryption
// disabled. It loads cleanly via config.Load but triggers the "encryption
// disabled" guard in every command that checks it before doing key/DB work.
const minimalConfigYAML = `
storage:
  type: local
  encryption:
    enabled: false
`

// badStorageConfigYAML is a YAML snippet that has an unsupported storage type.
// config.Load succeeds (YAML is syntactically valid), but openDatabase fails
// with "unknown storage type".
const badStorageConfigYAML = `
storage:
  type: badtype
  encryption:
    enabled: false
`

// writeConfig writes YAML content into a new temp dir as keyorix.yaml and
// returns its absolute path. Set KEYORIX_CONFIG_PATH to the returned path so
// loadConfig() finds it regardless of the working directory.
func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "keyorix.yaml")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// writeMinimalConfig writes a minimal keyorix.yaml (encryption disabled, local
// storage) into a new temp dir and returns its absolute path.
func writeMinimalConfig(t *testing.T) string {
	return writeConfig(t, minimalConfigYAML)
}

// ── runMigrateProviderCleanup ────────────────────────────────────────────────

// TestRunMigrateProviderCleanup_ConfigLoadError verifies the first error branch
// of runMigrateProviderCleanup: config.Load("") fails (no keyorix.yaml), and
// loadConfig wraps it with "failed to load configuration".
func TestRunMigrateProviderCleanup_ConfigLoadError(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_CONFIG_PATH", "") // ensure no override from environment

	err := migrateProviderCleanupCmd.RunE(migrateProviderCleanupCmd, nil)
	if err == nil {
		t.Fatal("expected config-load error, got nil")
	}
	// loadConfig wraps it as "failed to load configuration: ..."
	if !strings.Contains(err.Error(), "failed to load") {
		t.Errorf("expected 'failed to load' in error, got: %v", err)
	}
}

// TestRunMigrateProviderCleanup_EncryptionDisabledViaShim drives the full shim
// (runMigrateProviderCleanup) with a valid config that loads cleanly.
// encryption is disabled → migrateProviderCleanupWithConfig returns early
// before any key or file work. This covers statements 4 and 5 of the shim.
func TestRunMigrateProviderCleanup_EncryptionDisabledViaShim(t *testing.T) {
	cfgPath := writeMinimalConfig(t)
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	// Package-level cleanup flags — reset to safe values.
	old, oldDry := mpCleanupConfirm, mpCleanupDryRun
	mpCleanupConfirm = false
	mpCleanupDryRun = false
	t.Cleanup(func() { mpCleanupConfirm = old; mpCleanupDryRun = oldDry })

	err := migrateProviderCleanupCmd.RunE(migrateProviderCleanupCmd, nil)
	if err == nil {
		t.Fatal("expected disabled-encryption error, got nil")
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Errorf("expected 'disabled' in error, got: %v", err)
	}
}

// ── runMigrateProvider ───────────────────────────────────────────────────────

// TestRunMigrateProvider_ConfigLoadError verifies the first error branch of
// runMigrateProvider: config.Load("") fails (no keyorix.yaml).
func TestRunMigrateProvider_ConfigLoadError(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_CONFIG_PATH", "")

	err := migrateProviderCmd.RunE(migrateProviderCmd, nil)
	if err == nil {
		t.Fatal("expected config-load error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to load") {
		t.Errorf("expected 'failed to load' in error, got: %v", err)
	}
}

// TestRunMigrateProvider_EncryptionDisabledViaShim drives the full shim
// (runMigrateProvider) with a valid config that loads cleanly. encryption is
// disabled → migrateProviderWithConfig returns the "disabled" error before
// any key work. This covers statements 4 and beyond of the shim.
func TestRunMigrateProvider_EncryptionDisabledViaShim(t *testing.T) {
	cfgPath := writeMinimalConfig(t)
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	// Reset package-level migrate-provider flags to safe values.
	oldType, oldConfirm := mpToType, mpConfirm
	mpToType = "env"
	mpConfirm = false
	t.Cleanup(func() { mpToType = oldType; mpConfirm = oldConfirm })

	err := migrateProviderCmd.RunE(migrateProviderCmd, nil)
	if err == nil {
		t.Fatal("expected disabled-encryption error, got nil")
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Errorf("expected 'disabled' in error, got: %v", err)
	}
}

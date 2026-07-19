package startup

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minimalPermCheckConfigYAML returns a valid config with file permission checks
// ENABLED so that ValidateStartup exercises the security check branch.
func minimalPermCheckConfigYAML(absDBPath string) string {
	return fmt.Sprintf(`
storage:
  type: local
  database:
    path: %q
  encryption:
    enabled: false

server:
  http:
    enabled: false
  grpc:
    enabled: false

security:
  enable_file_permission_check: true
  allow_unsafe_file_permissions: false
`, absDBPath)
}

// minimalPermCheckAllowUnsafeConfigYAML is like minimalPermCheckConfigYAML but
// with allow_unsafe_file_permissions: true so that a perm-check failure becomes
// a warning instead of a hard error.
func minimalPermCheckAllowUnsafeConfigYAML(absDBPath string) string {
	return fmt.Sprintf(`
storage:
  type: local
  database:
    path: %q
  encryption:
    enabled: false

server:
  http:
    enabled: false
  grpc:
    enabled: false

security:
  enable_file_permission_check: true
  allow_unsafe_file_permissions: true
`, absDBPath)
}

// minimalEncryptionConfigYAML returns a valid config with encryption ENABLED so
// that ValidateStartup exercises the encryption validation branch.
func minimalEncryptionConfigYAML(absDBPath, saltPath, dekPath string) string {
	return fmt.Sprintf(`
storage:
  type: local
  database:
    path: %q
  encryption:
    enabled: true
    salt_path: %q
    dek_path: %q

server:
  http:
    enabled: false
  grpc:
    enabled: false

security:
  enable_file_permission_check: false
`, absDBPath, saltPath, dekPath)
}

// ---- ValidateStartup branch tests ----

// TestValidateStartup_PermCheckEnabled_BadMode exercises the branch where
// EnableFilePermissionCheck is true and the config file has wrong permissions
// (0644 instead of 0600), and AllowUnsafeFilePermissions is false.
// This covers lines 54-58 in ValidateStartup.
func TestValidateStartup_PermCheckEnabled_BadMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission modes not enforced on Windows")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "secrets.db")
	configPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(minimalPermCheckConfigYAML(dbPath)), 0644)) // wrong mode

	_, err := ValidateStartup(configPath, false)
	require.Error(t, err, "bad file mode with AllowUnsafe=false must return an error")
	assert.Contains(t, err.Error(), "permission")
}

// TestValidateStartup_PermCheckEnabled_AllowUnsafe exercises the branch where
// EnableFilePermissionCheck is true, the config file has wrong permissions, but
// AllowUnsafeFilePermissions is true — should succeed with a warning.
// This covers lines 59 in ValidateStartup.
func TestValidateStartup_PermCheckEnabled_AllowUnsafe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission modes not enforced on Windows")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "secrets.db")
	configPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(minimalPermCheckAllowUnsafeConfigYAML(dbPath)), 0644)) // wrong mode

	result, err := ValidateStartup(configPath, false)
	require.NoError(t, err, "AllowUnsafe=true must not return an error on perm failure")
	assert.NotEmpty(t, result.Warnings, "a perm-check failure with AllowUnsafe=true must produce a warning")
}

// TestValidateStartup_PermCheckEnabled_GoodMode exercises the branch where
// EnableFilePermissionCheck is true and all files have correct permissions.
// This covers lines 60-62 (result.PermissionsOK = true path).
func TestValidateStartup_PermCheckEnabled_GoodMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission modes not enforced on Windows")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "secrets.db")
	// The DB file must exist with the right mode so the perm check can stat it.
	require.NoError(t, os.WriteFile(dbPath, []byte("data"), 0600))
	configPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(minimalPermCheckConfigYAML(dbPath)), 0600)) // correct mode

	result, err := ValidateStartup(configPath, false)
	require.NoError(t, err)
	assert.True(t, result.PermissionsOK, "correct permissions must set PermissionsOK=true")
}

// TestValidateStartup_EncryptionEnabled_ValidKeys exercises the encryption branch
// where encryption is enabled and valid key files exist.
// This covers line 73 (result.EncryptionOK = true) in ValidateStartup.
func TestValidateStartup_EncryptionEnabled_ValidKeys(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "secrets.db")
	saltPath := filepath.Join(dir, "kek.salt")
	dekPath := filepath.Join(dir, "dek.key")
	require.NoError(t, os.WriteFile(saltPath, make([]byte, 32), 0600))
	require.NoError(t, os.WriteFile(dekPath, make([]byte, 60), 0600))

	configPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(minimalEncryptionConfigYAML(dbPath, saltPath, dekPath)), 0600))

	result, err := ValidateStartup(configPath, false)
	require.NoError(t, err)
	assert.True(t, result.EncryptionOK, "valid key files must set EncryptionOK=true")
}

// TestValidateStartup_DatabaseValidationFails exercises the path where
// validateDatabase returns an error — for local storage with a relative DB path.
// This covers lines 79-82 in ValidateStartup.
func TestValidateStartup_DatabaseValidationFails(t *testing.T) {
	dir := t.TempDir()
	// We need a config that passes schema validation but gives validateDatabase a
	// relative (unsafe) path. Use a custom config struct path injection: write a
	// config with a relative database path. Config.Validate() does not validate the
	// path value itself, only that the field is non-empty for local storage.
	configPath := filepath.Join(dir, "keyorix.yaml")
	// Use a relative path that will be rejected by validateDatabase.
	content := `
storage:
  type: local
  database:
    path: "relative.db"
  encryption:
    enabled: false

server:
  http:
    enabled: false
  grpc:
    enabled: false

security:
  enable_file_permission_check: false
`
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0600))

	_, err := ValidateStartup(configPath, false)
	require.Error(t, err, "a relative database path must cause database validation to fail")
	assert.Contains(t, err.Error(), "database")
}

// ---- validateFilePermissions branch tests ----

// TestValidateFilePermissions_HTTPTLSKeyTraversal exercises the error path where
// the HTTP TLS key path contains "..". This covers lines 162-164.
func TestValidateFilePermissions_HTTPTLSKeyTraversal(t *testing.T) {
	dir := t.TempDir()
	traversal := "sub/../../outside-target"

	cfg := &config.Config{}
	cfg.Server.HTTP.TLS.Enabled = true
	cfg.Server.HTTP.TLS.CertFile = filepath.Join(dir, "server.crt") // safe cert path
	cfg.Server.HTTP.TLS.KeyFile = traversal                          // unsafe key path

	err := validateFilePermissions(cfg, "", false, &ValidationResult{})
	require.Error(t, err, "HTTP TLS key path with '..' must be rejected")
	assert.Contains(t, err.Error(), "..")
}

// TestValidateFilePermissions_GRPCTLSCertTraversal exercises the error path where
// the gRPC TLS cert path contains "..". This covers lines 172-174.
func TestValidateFilePermissions_GRPCTLSCertTraversal(t *testing.T) {
	traversal := "sub/../../outside-target"

	cfg := &config.Config{}
	cfg.Server.GRPC.TLS.Enabled = true
	cfg.Server.GRPC.TLS.CertFile = traversal     // unsafe cert path
	cfg.Server.GRPC.TLS.KeyFile = "/safe/key/path" // safe key path (won't be reached)

	err := validateFilePermissions(cfg, "", false, &ValidationResult{})
	require.Error(t, err, "gRPC TLS cert path with '..' must be rejected")
	assert.Contains(t, err.Error(), "..")
}

// TestValidateFilePermissions_AutoFixViaConfigField exercises the autoFix warning
// path when cfg.Security.AutoFixFilePermissions is true (not forceAutoFix).
// This covers lines 185-192 (the autoFix warning branch).
func TestValidateFilePermissions_AutoFixViaConfigField(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission modes not enforced on Windows")
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "cfg.yaml")
	// Write with 0644 so it needs to be fixed, then autoFix=true will fix it.
	require.NoError(t, os.WriteFile(configPath, []byte("x"), 0644))

	cfg := &config.Config{}
	cfg.Security.AutoFixFilePermissions = true // autoFix via config field, not forceAutoFix
	result := &ValidationResult{}
	err := validateFilePermissions(cfg, configPath, false, result)
	require.NoError(t, err)
	assert.Contains(t, result.Warnings, "File permissions were automatically fixed",
		"autoFix via config field must append the 'fixed' warning")
}

// ---- validateDatabase branch tests ----

// TestValidateDatabase_CannotOpenFile exercises the error path where os.Open
// fails on a file that exists but is not readable (mode 0000).
// This covers lines 267-269.
func TestValidateDatabase_CannotOpenFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission modes not enforced on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("root bypasses permission checks")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "unreadable.db")
	require.NoError(t, os.WriteFile(dbPath, []byte("data"), 0600))
	// Remove all permissions so os.Open will fail even though the file exists.
	require.NoError(t, os.Chmod(dbPath, 0000))
	t.Cleanup(func() { _ = os.Chmod(dbPath, 0600) }) // restore for cleanup

	cfg := &config.Config{}
	cfg.Storage.Database.Path = dbPath
	result := &ValidationResult{}
	err := validateDatabase(cfg, result)
	require.Error(t, err, "unreadable DB file must return an error")
	assert.Contains(t, err.Error(), "cannot open database file")
}

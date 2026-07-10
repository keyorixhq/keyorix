package startup

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minimalConfigYAML returns a valid Keyorix config with:
//   - no HTTP/gRPC servers enabled (avoids port-required validation)
//   - local sqlite storage pointing at absDBPath
//   - encryption disabled (avoids key file requirements)
//   - file permission checks disabled (avoids chmod on the temp files)
func minimalConfigYAML(absDBPath string) string {
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
  enable_file_permission_check: false
`, absDBPath)
}

// writeConfig writes content to configPath.
func writeConfig(t *testing.T, configPath, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0600))
}

// TestValidateStartup_MissingConfigFile returns an error when the config file
// does not exist.
func TestValidateStartup_MissingConfigFile(t *testing.T) {
	_, err := ValidateStartup("/nonexistent/path/keyorix.yaml", false)
	require.Error(t, err)
}

// TestValidateStartup_ValidConfig returns a fully-OK result for a well-formed
// config (no encryption, no TLS, sqlite storage, file-perm checks off).
func TestValidateStartup_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "secrets.db")
	// The DB file doesn't have to exist — a missing file is a warning, not error.
	configPath := filepath.Join(dir, "keyorix.yaml")
	writeConfig(t, configPath, minimalConfigYAML(dbPath))

	result, err := ValidateStartup(configPath, false)
	require.NoError(t, err)
	assert.True(t, result.ConfigValid, "ConfigValid must be true")
	assert.True(t, result.PermissionsOK, "PermissionsOK must be true (checks disabled)")
	assert.True(t, result.EncryptionOK, "EncryptionOK must be true (encryption disabled)")
	assert.True(t, result.DatabaseOK, "DatabaseOK must be true")
}

// TestValidateStartup_ExistingDB verifies ValidateStartup accepts an existing,
// readable database file.
func TestValidateStartup_ExistingDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "secrets.db")
	require.NoError(t, os.WriteFile(dbPath, []byte("SQLite3 header"), 0600))
	configPath := filepath.Join(dir, "keyorix.yaml")
	writeConfig(t, configPath, minimalConfigYAML(dbPath))

	result, err := ValidateStartup(configPath, false)
	require.NoError(t, err)
	assert.True(t, result.DatabaseOK)
}

// TestValidateStartup_BadConfigSchema returns an error when the config content is
// structurally valid YAML but fails schema validation (e.g. HTTP server enabled
// without a port).
func TestValidateStartup_BadConfigSchema(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "keyorix.yaml")
	// HTTP enabled but no port → Validate() returns an error.
	writeConfig(t, configPath, `
server:
  http:
    enabled: true
`)
	_, err := ValidateStartup(configPath, false)
	require.Error(t, err, "a config that fails Validate() must return an error")
}

// TestValidateDatabase_TraversalPath verifies that a path containing ".." after
// Clean is rejected.
func TestValidateDatabase_TraversalPath(t *testing.T) {
	cfg := &config.Config{}
	cfg.Storage.Type = ""
	// "/../foo" after Clean is still absolute ("/foo") — use a relative traversal
	// to land on a non-absolute path after Clean.
	cfg.Storage.Database.Path = "../../relative.db"
	result := &ValidationResult{}
	err := validateDatabase(cfg, result)
	require.Error(t, err)
}

// TestValidateStartup_EncryptionEnabledMissingKeys returns an error when
// encryption is enabled but the key files don't exist.
func TestValidateStartup_EncryptionEnabledMissingKeys(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "secrets.db")
	configPath := filepath.Join(dir, "keyorix.yaml")
	// Use absolute paths for missing key files so validateEncryption path is reached.
	saltPath := filepath.Join(dir, "absent.salt")
	dekPath := filepath.Join(dir, "absent.dek")
	content := fmt.Sprintf(`
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
`, dbPath, saltPath, dekPath)
	writeConfig(t, configPath, content)

	_, err := ValidateStartup(configPath, false)
	require.Error(t, err, "missing encryption key files must result in an error")
}

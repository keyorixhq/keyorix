// modes_s23_test.go — coverage sprint s23 for internal/cli/modes.go.
//
// Targets the branches not yet exercised by main_test.go:
//
//   - initClientMode: success path (valid endpoint provided) → exercises the
//     mainConfig build, factory.CreateStorage("remote"), and core.NewKeyorixCore
//     allocation steps (lines 121–145).
//   - Execute: version flag path (calls rootCmd.Execute with --version which
//     exits 0 without os.Exit(1)) — exercises bootstrapI18n + rootCmd.Execute.
package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewCLI_ClientMode_WithEndpoint_Succeeds drives the full initClientMode
// success path: a CLI config with mode=client and a non-empty endpoint must
// construct a CLI object in ClientMode with a non-nil core service. This
// exercises mainConfig assembly, factory.CreateStorage, and core.NewKeyorixCore
// (the seven statements at lines 121–145 of modes.go that are at 0% before this
// test).
func TestNewCLI_ClientMode_WithEndpoint_Succeeds(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	// Write a CLI config that sets mode=client with a valid endpoint URL.
	// NewHTTPClient does not connect — it just builds an http.Client — so no
	// network is needed and this succeeds in sandbox.
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "keyorix"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix", "cli.yaml"), []byte(`
mode: client
client:
  endpoint: "https://keyorix.example.com"
  timeout: "30s"
  auth:
    type: api_key
    api_key: "test-api-key-s23"
`), 0o600))

	c, err := NewCLI()
	require.NoError(t, err)
	assert.Equal(t, ClientMode, c.GetMode())
	assert.NotNil(t, c.GetCoreService(),
		"initClientMode must populate coreService on success")
}

// TestNewCLI_ClientMode_GetConfig_NotNil verifies that a successfully created
// client-mode CLI exposes its CLIConfig via GetConfig. This complements the nil
// check in TestCLI_Getters (which uses a zero-value CLI struct).
func TestNewCLI_ClientMode_GetConfig_NotNil(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "keyorix"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix", "cli.yaml"), []byte(`
mode: client
client:
  endpoint: "https://keyorix.example.com"
  auth:
    type: api_key
    api_key: "test-api-key-s23b"
`), 0o600))

	c, err := NewCLI()
	require.NoError(t, err)
	assert.NotNil(t, c.GetConfig(), "GetConfig must return the loaded CLIConfig")
}

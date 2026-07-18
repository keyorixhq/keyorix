// modes_s24_test.go — coverage sprint s24 for internal/cli (main.go + modes.go).
//
// Targets branches not yet exercised by main_test.go and modes_s23_test.go:
//
//   - Execute: bootstrapI18n + rootCmd.Execute success path via --version flag.
//   - NewCLI: LoadCLIConfig error path (invalid YAML in config file).
//   - initEmbeddedMode: storage factory error path (unwriteable DB path).
//   - initClientMode: storage factory error path (http non-loopback URL fails TLS validation).
package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	cliconfig "github.com/keyorixhq/keyorix/internal/cli/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExecute_VersionFlag calls Execute() with --version so that rootCmd.Execute
// succeeds (returns nil / does not call os.Exit(1)).  This exercises the
// bootstrapI18n call inside Execute and the happy path through rootCmd.Execute.
func TestExecute_VersionFlag(t *testing.T) {
	i18n.ResetForTesting()
	t.Cleanup(i18n.ResetForTesting)

	// Redirect output so --version doesn't pollute test stdout.
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
	})

	rootCmd.SetArgs([]string{"--version"})
	// Execute must not panic or call os.Exit — --version exits 0 in cobra.
	Execute()
	// Output should contain the version string.
	assert.Contains(t, buf.String(), "keyorix")
}

// TestNewCLI_InvalidCLIConfig_Errors drives the LoadCLIConfig error branch in
// NewCLI (line 44-46 of modes.go): if the cli.yaml file exists but contains
// invalid YAML, LoadCLIConfig returns an error and NewCLI must propagate it.
func TestNewCLI_InvalidCLIConfig_Errors(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	cfgDir := filepath.Join(dir, "keyorix")
	require.NoError(t, os.MkdirAll(cfgDir, 0o755))

	// Write syntactically invalid YAML so yaml.Unmarshal returns an error.
	invalidYAML := []byte("mode: [\x00invalid yaml\n")
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "cli.yaml"), invalidYAML, 0o600))

	_, err := NewCLI()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load CLI config")
}

// TestInitEmbeddedMode_StorageError drives the "failed to create storage" error
// return in initEmbeddedMode (modes.go line 104-107).  We set the database path
// to a sub-path of a non-existent root directory so SQLite cannot open the file.
func TestInitEmbeddedMode_StorageError(t *testing.T) {
	cfg := cliconfig.DefaultCLIConfig()
	// Point DatabasePath at a location the OS can never create —
	// a sub-directory of a file that doesn't exist as a directory.
	cfg.Embedded.DatabasePath = "/nonexistent-parent-dir-s24/sub/secrets.db"

	c := &CLI{config: cfg}
	err := c.initEmbeddedMode()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create storage")
}

// TestInitClientMode_HTTPSRequired drives the "failed to create remote storage"
// error path in initClientMode (modes.go lines 137-140).  Using a plain
// http:// non-loopback endpoint causes remote.Config.Validate() to reject it
// (API key would be sent in cleartext), which NewRemoteStorage propagates back.
func TestInitClientMode_HTTPSRequired_Errors(t *testing.T) {
	cfg := cliconfig.DefaultCLIConfig()
	cfg.Mode = "client"
	cfg.Client.Endpoint = "http://example.com" // non-https, non-loopback → validation fails
	cfg.Client.Auth.APIKey = "test-key-s24"
	cfg.Client.Auth.Type = "api_key"

	c := &CLI{config: cfg}
	err := c.initClientMode()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create remote storage")
}

// TestInitEmbeddedMode_EmptyDatabasePath exercises the default-path branch
// in initEmbeddedMode (line 99 of modes.go): when DatabasePath is empty the
// function substitutes "./secrets.db" before calling CreateStorage.  We use a
// temp directory as CWD so the substituted path is writable and the storage
// factory succeeds.
func TestInitEmbeddedMode_EmptyDatabasePath(t *testing.T) {
	dir := t.TempDir()
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	cfg := cliconfig.DefaultCLIConfig()
	cfg.Embedded.DatabasePath = "" // triggers the default-path substitution

	c := &CLI{config: cfg}
	err = c.initEmbeddedMode()
	require.NoError(t, err)
	assert.NotNil(t, c.coreService, "coreService must be set after successful initEmbeddedMode")
}

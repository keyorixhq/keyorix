package auth

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunLogin_ServerRequired exercises the "server URL is required" error branch in
// runLogin.  An API key is available via the env var so ResolveAPIKey returns a
// non-empty value, but no --server flag and no existing remote config are present,
// causing server to remain "".
func TestRunLogin_ServerRequired(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	t.Setenv("KEYORIX_API_KEY", "kx_test_key_123")

	// Ensure the --server flag is cleared.
	_ = loginCmd.Flags().Set("server", "")
	loginCmd.Flags().Lookup("server").Changed = false
	t.Cleanup(func() {
		_ = loginCmd.Flags().Set("server", "")
		loginCmd.Flags().Lookup("server").Changed = false
	})

	// No keyorix.yaml and no server flag → runLogin must return "server URL is required".
	err := runLogin(loginCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server URL is required")
}

// TestRunLogin_SaveFails exercises the config.Save error branch inside runLogin.
// The test makes the working directory read-only so the YAML write fails.
func TestRunLogin_SaveFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod read-only not reliable on Windows")
	}

	dir := t.TempDir()
	t.Chdir(dir)

	t.Setenv("KEYORIX_API_KEY", "kx_test_key_456")

	require.NoError(t, loginCmd.Flags().Set("server", "https://keyorix.example.com"))
	t.Cleanup(func() {
		// Restore write permission before TempDir cleanup.
		_ = os.Chmod(dir, 0700)
		_ = loginCmd.Flags().Set("server", "")
		loginCmd.Flags().Lookup("server").Changed = false
	})

	// Make the directory read-only so config.Save cannot write keyorix.yaml.
	require.NoError(t, os.Chmod(dir, 0500))

	err := runLogin(loginCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save configuration")
}

// TestRunLogout_SaveFails exercises the config.Save error branch inside runLogout.
// A valid keyorix.yaml is written first, then the file itself is made read-only so
// the subsequent write during Save fails with a permission error.
func TestRunLogout_SaveFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod read-only not reliable on Windows")
	}

	dir := t.TempDir()
	t.Chdir(dir)

	// Write a minimal valid config so config.Load succeeds.
	yaml := "storage:\n  type: remote\n  remote:\n    base_url: https://keyorix.example.com\n"
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(yaml), 0600))

	t.Cleanup(func() {
		_ = os.Chmod(cfgPath, 0600)
	})

	// Make the config file itself read-only so config.Save cannot open it for writing.
	require.NoError(t, os.Chmod(cfgPath, 0400))

	err := runLogout(logoutCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save configuration")
}

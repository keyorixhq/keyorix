// config_s26_test.go — s26 coverage for internal/cli/config.
//
// Gaps targeted:
//   - runStatus remote branch with no API key → "(not set)" output
//   - runStatus local branch where DB file already exists → "Database file exists"
//   - testRemoteConnection with non-nil Remote config but empty BaseURL
package config

import (
	"os"
	"path/filepath"
	"testing"

	appconfig "github.com/keyorixhq/keyorix/internal/config"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunStatus_RemoteNoAPIKey exercises the runStatus path where the storage
// type is "remote" and the API key field is empty, producing "(not set)" output.
func TestRunStatus_RemoteNoAPIKey(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	yaml := "storage:\n  type: remote\n  remote:\n    base_url: https://keyorix.example.com\n    timeout_seconds: 30\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(yaml), 0600))

	cmd := &cobra.Command{}
	require.NoError(t, runStatus(cmd, nil))
}

// TestRunStatus_LocalDBExists exercises the runStatus path where the local DB
// file already exists on disk, producing the "Database file exists" status line.
func TestRunStatus_LocalDBExists(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	dbPath := filepath.Join(dir, "secrets.db")
	require.NoError(t, os.WriteFile(dbPath, []byte{}, 0600))

	yaml := "storage:\n  type: local\n  database:\n    path: " + dbPath + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(yaml), 0600))

	cmd := &cobra.Command{}
	require.NoError(t, runStatus(cmd, nil))
}

// TestTestRemoteConnection_EmptyBaseURL exercises the guard in testRemoteConnection
// that fires when the Remote config struct is present but BaseURL is empty.
func TestTestRemoteConnection_EmptyBaseURL(t *testing.T) {
	cfg := &appconfig.Config{}
	cfg.Storage.Type = "remote"
	cfg.Storage.Remote = &appconfig.RemoteConfig{BaseURL: ""}

	err := testRemoteConnection(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "URL not configured")
}

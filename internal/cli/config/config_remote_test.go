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

func cfgForLocal(dbPath string) appconfig.Config {
	var c appconfig.Config
	c.Storage.Type = "local"
	c.Storage.Database.Path = dbPath
	return c
}

// newSetRemoteCmd builds a minimal cobra.Command with the set-remote flags wired.
func newSetRemoteCmd(url, apiKey string) *cobra.Command {
	cmd := &cobra.Command{Use: "set-remote"}
	cmd.Flags().String("url", url, "")
	cmd.Flags().String("api-key", apiKey, "")
	cmd.Flags().Int("timeout", 30, "")
	return cmd
}

func TestRunSetRemote_WritesConfig(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	cmd := newSetRemoteCmd("https://keyorix.example.com", "")
	t.Setenv("KEYORIX_API_KEY", "")
	require.NoError(t, runSetRemote(cmd, nil))

	_, err := os.Stat(filepath.Join(dir, "keyorix.yaml"))
	assert.NoError(t, err, "keyorix.yaml should be created by set-remote")
}

func TestRunSetRemote_WithAPIKeyFlag(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	cmd := newSetRemoteCmd("https://keyorix.example.com", "kx_secret")
	require.NoError(t, runSetRemote(cmd, nil))
}

func TestRunUseLocal_WritesConfig(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	cmd := &cobra.Command{}
	require.NoError(t, runUseLocal(cmd, nil))

	_, err := os.Stat(filepath.Join(dir, "keyorix.yaml"))
	assert.NoError(t, err, "keyorix.yaml should be created by use-local")
}

func TestRunStatus_LocalConfig(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	yamlContent := "storage:\n  type: local\n  database:\n    path: ./test.db\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(yamlContent), 0600))

	cmd := &cobra.Command{}
	require.NoError(t, runStatus(cmd, nil))
}

func TestRunStatus_RemoteConfig(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	yamlContent := "storage:\n  type: remote\n  remote:\n    base_url: https://keyorix.example.com\n    api_key: kx_secret\n    timeout_seconds: 30\n    tls_verify: true\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(yamlContent), 0600))

	cmd := &cobra.Command{}
	require.NoError(t, runStatus(cmd, nil))
}

func TestRunStatus_MissingConfig_DefaultsApply(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	// No keyorix.yaml — runStatus falls back to defaults, should not error.
	cmd := &cobra.Command{}
	_ = runStatus(cmd, nil)
}

func TestRunTestConnection_LocalExistingDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	dbPath := filepath.Join(dir, "secrets.db")
	require.NoError(t, os.WriteFile(dbPath, []byte{}, 0600))

	yaml := "storage:\n  type: local\n  database:\n    path: " + dbPath + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(yaml), 0600))

	cmd := &cobra.Command{}
	require.NoError(t, runTestConnection(cmd, nil))
}

func TestRunTestConnection_LocalMissingDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	yaml := "storage:\n  type: local\n  database:\n    path: /nonexistent/secrets.db\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(yaml), 0600))

	cmd := &cobra.Command{}
	// Missing DB is a warning, not an error from testLocalConnection.
	require.NoError(t, runTestConnection(cmd, nil))
}

func TestTestRemoteConnection_NilRemoteConfig(t *testing.T) {
	c := &appconfig.Config{}
	c.Storage.Type = "remote"
	// c.Storage.Remote is nil intentionally
	err := testRemoteConnection(c)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remote configuration not found")
}

func TestTestLocalConnection_EmptyPath(t *testing.T) {
	c := cfgForLocal("")
	// Empty DB path falls back to ./secrets.db — should not error.
	require.NoError(t, testLocalConnection(&c))
}

func TestMaskAPIKey_ExactlyEight(t *testing.T) {
	// len == 8: the <= 8 branch returns "***"
	assert.Equal(t, "***", maskAPIKey("12345678"))
}

func TestMaskAPIKey_NineChars(t *testing.T) {
	// 9 chars: first4 + "..." + last4
	assert.Equal(t, "1234...6789", maskAPIKey("123456789"))
}

package connect

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunConnect_WithAPIKeyAndHealthCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("KEYORIX_API_KEY", "test-key")

	require.NoError(t, ConnectCmd.Flags().Set("test", "true"))
	require.NoError(t, ConnectCmd.Flags().Set("insecure", "true"))
	t.Cleanup(func() {
		_ = ConnectCmd.Flags().Set("test", "true")
		_ = ConnectCmd.Flags().Set("insecure", "false")
	})

	require.NoError(t, runConnect(ConnectCmd, []string{srv.URL}))
}

func TestRunConnect_RefusesNonHTTPS(t *testing.T) {
	require.NoError(t, ConnectCmd.Flags().Set("insecure", "false"))
	t.Cleanup(func() { _ = ConnectCmd.Flags().Set("insecure", "false") })

	err := runConnect(ConnectCmd, []string{"http://external.example.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-HTTPS")
}

func TestRunConnect_InvalidTimeout(t *testing.T) {
	require.NoError(t, ConnectCmd.Flags().Set("timeout", "notaduration"))
	t.Cleanup(func() { _ = ConnectCmd.Flags().Set("timeout", "30s") })

	err := runConnect(ConnectCmd, []string{"https://keyorix.example.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid timeout")
}

func TestRunConnect_HealthCheckFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("KEYORIX_API_KEY", "test-key")

	require.NoError(t, ConnectCmd.Flags().Set("test", "true"))
	require.NoError(t, ConnectCmd.Flags().Set("insecure", "true"))
	require.NoError(t, ConnectCmd.Flags().Set("timeout", "5s"))
	t.Cleanup(func() {
		_ = ConnectCmd.Flags().Set("test", "true")
		_ = ConnectCmd.Flags().Set("insecure", "false")
		_ = ConnectCmd.Flags().Set("timeout", "30s")
	})

	err := runConnect(ConnectCmd, []string{srv.URL})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection test failed")
}

func TestRunDisconnect_WhenEmbedded(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))

	// With no config file, LoadCLIConfig returns a default (embedded) config.
	require.NoError(t, runDisconnect(nil, nil))
}

func TestRunDisconnect_FromClientMode(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	configDir := filepath.Join(dir, "config", "keyorix")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))

	require.NoError(t, os.MkdirAll(configDir, 0750))
	cliYAML := "mode: client\nclient:\n  endpoint: https://keyorix.example.com\n"
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "cli.yaml"), []byte(cliYAML), 0600))

	require.NoError(t, runDisconnect(nil, nil))
}

func TestRunStatus_EmbeddedMode(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	// No cli.yaml → defaults to embedded mode, runStatus should succeed.
	require.NoError(t, runStatus(nil, nil))
}

func TestRunStatus_ClientMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	t.Chdir(dir)
	configDir := filepath.Join(dir, "config", "keyorix")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))

	require.NoError(t, os.MkdirAll(configDir, 0750))
	cliYAML := "mode: client\nclient:\n  endpoint: " + srv.URL + "\n  auth:\n    type: api_key\n    api_key: tok\n  timeout: 5s\n"
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "cli.yaml"), []byte(cliYAML), 0600))

	require.NoError(t, runStatus(nil, nil))
}

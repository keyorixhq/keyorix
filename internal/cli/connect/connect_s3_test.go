// connect_s3_test.go — sprint-3 coverage: connectHTTPClient's redirect refusal,
// the "no API key" tip branch in runConnect, LoadCLIConfig/SaveCLIConfig failure
// paths across runConnect/runDisconnect/runStatus, and the "failed to create
// request" branches in loginWithCredentials/testServerConnection.
package connect

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	cliconfig "github.com/keyorixhq/keyorix/internal/cli/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRefuseConnectRedirect verifies the CheckRedirect callback itself rejects
// any redirect with a descriptive error naming the target URL.
func TestRefuseConnectRedirect(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://internal.example.com/evil", nil)
	require.NoError(t, err)

	err = refuseConnectRedirect(req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to follow redirect")
	assert.Contains(t, err.Error(), "internal.example.com/evil")
}

// TestConnectHTTPClient_RefusesRedirect is the end-to-end regression test for
// CWE-918: a server that responds with a 3xx pointing somewhere else (e.g. an
// internal metadata endpoint) must not be silently followed by the shared
// connectHTTPClient used by testServerConnection/loginWithCredentials.
func TestConnectHTTPClient_RefusesRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	err := testServerConnection(srv.URL, "key", 5*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to follow redirect")
}

// TestRunConnect_NoAPIKeyPrintsTip exercises the branch where runConnect
// finishes with an empty resolved API key (no --api-key, no KEYORIX_API_KEY,
// no --username login): the saved config must persist "no auth" rather than a
// stray empty-string key mistaken for a real one.
func TestRunConnect_NoAPIKeyPrintsTip(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("KEYORIX_API_KEY", "")

	require.NoError(t, ConnectCmd.Flags().Set("username", ""))
	require.NoError(t, ConnectCmd.Flags().Set("api-key", ""))
	require.NoError(t, ConnectCmd.Flags().Set("insecure", "false"))
	require.NoError(t, ConnectCmd.Flags().Set("test", "false"))
	t.Cleanup(func() {
		_ = ConnectCmd.Flags().Set("insecure", "false")
		_ = ConnectCmd.Flags().Set("test", "false")
	})

	require.NoError(t, runConnect(ConnectCmd, []string{"https://keyorix.example.com"}))

	cfg, err := cliconfig.LoadCLIConfig("")
	require.NoError(t, err)
	assert.Equal(t, "client", cfg.Mode)
	assert.Equal(t, "none", cfg.Client.Auth.Type)
	assert.Equal(t, "", cfg.Client.Auth.APIKey)
}

// TestRunConnect_UnreadableConfigFallsBackToDefault verifies that when the
// existing cli.yaml can't be read (here: the path is a directory, not a file),
// runConnect swallows that LoadCLIConfig error and proceeds with a fresh
// default config rather than failing the whole command.
func TestRunConnect_UnreadableConfigFallsBackToDefault(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	configDir := filepath.Join(dir, "config", "keyorix")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	require.NoError(t, os.MkdirAll(configDir, 0750))
	// A directory where cli.yaml is expected makes os.ReadFile fail.
	require.NoError(t, os.MkdirAll(filepath.Join(configDir, "cli.yaml"), 0750))

	require.NoError(t, ConnectCmd.Flags().Set("insecure", "false"))
	require.NoError(t, ConnectCmd.Flags().Set("test", "false"))
	t.Cleanup(func() {
		_ = ConnectCmd.Flags().Set("insecure", "false")
		_ = ConnectCmd.Flags().Set("test", "false")
	})

	err := runConnect(ConnectCmd, []string{"https://keyorix.example.com"})
	// SaveCLIConfig will also fail to write through the cli.yaml directory
	// (can't create a regular file where a directory already exists), so the
	// overall command surfaces that later failure — but it must be the SAVE
	// error, not a load/config-parsing failure, proving the load error was
	// swallowed and a default config was used instead.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save configuration")
}

// TestRunConnect_SaveConfigFails verifies that a directory-creation failure in
// SaveCLIConfig (a regular file sits where the config directory must go) is
// propagated as "failed to save configuration".
func TestRunConnect_SaveConfigFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	xdg := filepath.Join(dir, "config")
	require.NoError(t, os.MkdirAll(xdg, 0750))
	// Block the "keyorix" config subdirectory with a plain file, so
	// os.MkdirAll(dir) inside SaveCLIConfig fails with "not a directory".
	require.NoError(t, os.WriteFile(filepath.Join(xdg, "keyorix"), []byte("blocker"), 0600))
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("KEYORIX_API_KEY", "test-key")

	require.NoError(t, ConnectCmd.Flags().Set("insecure", "false"))
	require.NoError(t, ConnectCmd.Flags().Set("test", "false"))
	t.Cleanup(func() {
		_ = ConnectCmd.Flags().Set("insecure", "false")
		_ = ConnectCmd.Flags().Set("test", "false")
	})

	err := runConnect(ConnectCmd, []string{"https://keyorix.example.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save configuration")
}

// TestRunDisconnect_LoadConfigFails verifies that a cli.yaml that can't be
// read (here: it's a directory) makes runDisconnect return "failed to load
// configuration" rather than silently defaulting (unlike runConnect, which
// intentionally falls back).
func TestRunDisconnect_LoadConfigFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	configDir := filepath.Join(dir, "config", "keyorix")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	require.NoError(t, os.MkdirAll(configDir, 0750))
	require.NoError(t, os.MkdirAll(filepath.Join(configDir, "cli.yaml"), 0750))

	err := runDisconnect(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load configuration")
}

// TestRunDisconnect_SaveConfigFails verifies that a save failure after a
// successful load (client mode, so SetEmbeddedMode+Save is reached) is
// propagated as "failed to save configuration". The existing cli.yaml file is
// made read-only so the open-for-write in SaveCLIConfig fails with EACCES.
func TestRunDisconnect_SaveConfigFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	configDir := filepath.Join(dir, "config", "keyorix")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	require.NoError(t, os.MkdirAll(configDir, 0750))

	cliYAML := "mode: client\nclient:\n  endpoint: https://keyorix.example.com\n"
	cliPath := filepath.Join(configDir, "cli.yaml")
	require.NoError(t, os.WriteFile(cliPath, []byte(cliYAML), 0600))
	require.NoError(t, os.Chmod(cliPath, 0400))
	t.Cleanup(func() { _ = os.Chmod(cliPath, 0600) })

	err := runDisconnect(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save configuration")
}

// TestRunStatus_LoadConfigFails verifies that an unreadable cli.yaml (a
// directory in place of the file) surfaces as "failed to load configuration"
// from runStatus.
func TestRunStatus_LoadConfigFails(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	configDir := filepath.Join(dir, "config", "keyorix")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	require.NoError(t, os.MkdirAll(configDir, 0750))
	require.NoError(t, os.MkdirAll(filepath.Join(configDir, "cli.yaml"), 0750))

	err := runStatus(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load configuration")
}

// TestLoginWithCredentials_Unreachable verifies the connectHTTPClient.Do
// failure branch: a refused TCP connection is wrapped as "request failed".
func TestLoginWithCredentials_Unreachable(t *testing.T) {
	_, err := loginWithCredentials("http://127.0.0.1:1", "alice", "pw", 2*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request failed")
}

// TestLoginWithCredentials_InvalidURL verifies the http.NewRequestWithContext
// failure branch: an endpoint containing a raw control byte is rejected by
// net/url before any network I/O, wrapped as "failed to create request".
func TestLoginWithCredentials_InvalidURL(t *testing.T) {
	_, err := loginWithCredentials("http://example.com/\x7f\x01", "alice", "pw", 2*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create request")
}

// TestTestServerConnection_InvalidURL is the same http.NewRequestWithContext
// failure branch, exercised via testServerConnection instead.
func TestTestServerConnection_InvalidURL(t *testing.T) {
	err := testServerConnection("http://example.com/\x7f\x01", "key", 2*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create request")
}

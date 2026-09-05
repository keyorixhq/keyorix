package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFakeProfileServer starts an httptest server that answers GET /auth/profile
// the way the real server does (envelope-wrapped JSON with a username), so tests
// can exercise runLogin's post-#B3 verifyRemoteCredentials call without a real
// Keyorix server. Requiring this round-trip to succeed before runLogin persists
// anything or prints "Successfully authenticated" is the fix itself (previously
// runLogin wrote storage.type: remote and printed that message for ANY
// server/API key with no verification at all).
func newFakeProfileServer(t *testing.T, username string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/profile" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"username": username},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRunLogin_HappyPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	srv := newFakeProfileServer(t, "alice")

	// Set the API key via env so no interactive prompt is triggered.
	t.Setenv("KEYORIX_API_KEY", "kx_env_secret")

	require.NoError(t, loginCmd.Flags().Set("server", srv.URL))
	t.Cleanup(func() {
		_ = loginCmd.Flags().Set("server", "")
		loginCmd.Flags().Lookup("server").Changed = false
	})

	require.NoError(t, runLogin(loginCmd, nil))

	// A keyorix.yaml should have been written.
	_, err := os.Stat(filepath.Join(dir, "keyorix.yaml"))
	assert.NoError(t, err, "keyorix.yaml should be created by runLogin")
}

func TestRunLogin_NoAPIKeyNoServer(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_API_KEY", "")

	err := runLogin(loginCmd, nil)
	// Should fail: either "API key is required" or "server URL is required" depending
	// on whether a config with remote settings exists.
	require.Error(t, err)
}

func TestRunLogin_ServerFromExistingConfig(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	srv := newFakeProfileServer(t, "bob")

	// Pre-write a keyorix.yaml with a remote section so runLogin can pick up the server.
	yaml := "storage:\n  type: remote\n  remote:\n    base_url: " + srv.URL + "\n    tls_verify: true\n    timeout_seconds: 30\n"
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(yaml), 0600))

	t.Setenv("KEYORIX_API_KEY", "kx_env_key")

	// #G73: a server URL sourced from ./keyorix.yaml (untrusted, CWD-relative,
	// attacker-plantable) is about to have a freshly-entered real API key
	// persisted against it — this must warn, the same way ResolveRemote's
	// other CLI callers already do.
	out := captureStderr(t, func() {
		require.NoError(t, runLogin(loginCmd, nil))
	})
	assert.Contains(t, out, "keyorix.yaml")
	assert.Contains(t, out, "malicious file")
}

func TestRunLogout_WritesLocalConfig(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	// Start with a remote config.
	yaml := "storage:\n  type: remote\n  remote:\n    base_url: https://keyorix.example.com\n"
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(yaml), 0600))

	require.NoError(t, runLogout(logoutCmd, nil))

	// Should have written a local-mode config.
	data, err := os.ReadFile("keyorix.yaml")
	require.NoError(t, err)
	assert.Contains(t, string(data), "local")
}

func TestRunLogout_NoExistingConfig(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	// No keyorix.yaml — runLogout should fail because config.Load returns an error
	// when no file is present.
	err := runLogout(logoutCmd, nil)
	require.Error(t, err)
}

func TestRunStatus_LocalStorage(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	yaml := "storage:\n  type: local\n  database:\n    path: ./secrets.db\n"
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(yaml), 0600))

	require.NoError(t, runStatus(statusCmd, nil))
}

func TestRunStatus_RemoteStorage(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	yaml := "storage:\n  type: remote\n  remote:\n    base_url: https://keyorix.example.com\n    api_key: kx_tok\n"
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(yaml), 0600))

	require.NoError(t, runStatus(statusCmd, nil))
}

func TestRunStatus_RemoteStorage_NoAPIKey(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	yaml := "storage:\n  type: remote\n  remote:\n    base_url: https://keyorix.example.com\n"
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(yaml), 0600))

	require.NoError(t, runStatus(statusCmd, nil))
}

func TestRunStatus_RemoteStorage_NilRemote(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	// type=remote but no remote section — exercises the nil-remote branch.
	yaml := "storage:\n  type: remote\n"
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(yaml), 0600))

	require.NoError(t, runStatus(statusCmd, nil))
}

func TestRunStatus_MissingConfig(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	// No config file — runStatus prints "No configuration found" and returns nil.
	require.NoError(t, runStatus(statusCmd, nil))
}

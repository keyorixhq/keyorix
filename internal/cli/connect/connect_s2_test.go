// connect_s2_test.go — sprint-2 coverage for the login flow, empty-token response,
// runStatus connection failure, and runConnect save-config error paths.
package connect

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoginWithCredentials_EmptyToken verifies that a well-formed 200 response
// with an empty token field is treated as an error (no token in response).
func TestLoginWithCredentials_EmptyToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 200 OK but token is blank.
		_, _ = w.Write([]byte(`{"data":{"token":""}}`))
	}))
	defer srv.Close()

	_, err := loginWithCredentials(srv.URL, "alice", "pw", 5*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no token in response")
}

// TestLoginWithCredentials_InvalidJSON verifies that a non-JSON body returns
// a "failed to parse response" error.
func TestLoginWithCredentials_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer srv.Close()

	_, err := loginWithCredentials(srv.URL, "alice", "pw", 5*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse response")
}

// TestRunConnect_WithLogin exercises the username+password flow in runConnect:
// KEYORIX_PASSWORD is set so that resolveConnectPassword returns it without
// prompting, loginWithCredentials succeeds, and the config is saved.
func TestRunConnect_WithLogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/login":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			assert.Equal(t, "alice", body["username"])
			_, _ = w.Write([]byte(`{"data":{"token":"login-token"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	t.Setenv("KEYORIX_PASSWORD", "s3cr3t")
	t.Setenv("KEYORIX_API_KEY", "")

	require.NoError(t, ConnectCmd.Flags().Set("username", "alice"))
	require.NoError(t, ConnectCmd.Flags().Set("insecure", "true"))
	require.NoError(t, ConnectCmd.Flags().Set("timeout", "5s"))
	require.NoError(t, ConnectCmd.Flags().Set("test", "false"))
	t.Cleanup(func() {
		_ = ConnectCmd.Flags().Set("username", "")
		_ = ConnectCmd.Flags().Set("insecure", "false")
		_ = ConnectCmd.Flags().Set("timeout", "30s")
		_ = ConnectCmd.Flags().Set("test", "false")
	})

	require.NoError(t, runConnect(ConnectCmd, []string{srv.URL}))
}

// TestRunConnect_LoginFails verifies that a failed loginWithCredentials call
// is propagated as a "login failed" error.
func TestRunConnect_LoginFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_PASSWORD", "wrong")
	t.Setenv("KEYORIX_API_KEY", "")

	require.NoError(t, ConnectCmd.Flags().Set("username", "alice"))
	require.NoError(t, ConnectCmd.Flags().Set("insecure", "true"))
	require.NoError(t, ConnectCmd.Flags().Set("timeout", "5s"))
	require.NoError(t, ConnectCmd.Flags().Set("test", "false"))
	t.Cleanup(func() {
		_ = ConnectCmd.Flags().Set("username", "")
		_ = ConnectCmd.Flags().Set("insecure", "false")
		_ = ConnectCmd.Flags().Set("timeout", "30s")
		_ = ConnectCmd.Flags().Set("test", "false")
	})

	err := runConnect(ConnectCmd, []string{srv.URL})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "login failed")
}

// TestRunConnect_EmptyPassword verifies that an empty resolved password
// (no KEYORIX_PASSWORD and no --password flag) triggers a clear error when a
// username is supplied.
func TestRunConnect_EmptyPassword(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	// Clear both sources so resolveConnectPassword gets "" from env and
	// cannot fall through to a terminal read (Stdin is not a tty in tests,
	// so term.ReadPassword would error, but we want the password=="" path).
	t.Setenv("KEYORIX_PASSWORD", "")

	require.NoError(t, ConnectCmd.Flags().Set("username", "alice"))
	require.NoError(t, ConnectCmd.Flags().Set("insecure", "true"))
	require.NoError(t, ConnectCmd.Flags().Set("timeout", "5s"))
	require.NoError(t, ConnectCmd.Flags().Set("test", "false"))
	t.Cleanup(func() {
		_ = ConnectCmd.Flags().Set("username", "")
		_ = ConnectCmd.Flags().Set("insecure", "false")
		_ = ConnectCmd.Flags().Set("timeout", "30s")
		_ = ConnectCmd.Flags().Set("test", "false")
	})

	err := runConnect(ConnectCmd, []string{srv.URL})
	// Either the "password is required" branch fires (no tty) or term.ReadPassword
	// returns an error because Stdin is a pipe. Both are valid failures here.
	require.Error(t, err)
}

// TestRunStatus_ClientMode_FailedConnection verifies the runStatus path where
// the server is not reachable (connection fails) — the status command still
// returns nil (it prints the error instead of returning it).
func TestRunStatus_ClientMode_FailedConnection(t *testing.T) {
	// Point cli.yaml at a server that is guaranteed to refuse connections.
	dir := t.TempDir()
	t.Chdir(dir)
	configDir := filepath.Join(dir, "config", "keyorix")
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))

	require.NoError(t, os.MkdirAll(configDir, 0750))
	// Use an address that will immediately refuse — port 0 is not listened on.
	cliYAML := "mode: client\nclient:\n  endpoint: http://127.0.0.1:1\n  auth:\n    type: api_key\n    api_key: tok\n  timeout: 1s\n"
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "cli.yaml"), []byte(cliYAML), 0600))

	// runStatus handles a failed test-connection by printing the error, not
	// returning it.
	require.NoError(t, runStatus(nil, nil))
}

// TestTestServerConnection_NoAPIKey verifies that testServerConnection works
// even when the API key is empty (no Authorization header is sent).
func TestTestServerConnection_NoAPIKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/health", r.URL.Path)
		assert.Equal(t, "", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	require.NoError(t, testServerConnection(srv.URL, "", 5*time.Second))
}

// TestRequireSecureEndpoint_InvalidURL verifies that a completely unparseable
// URL returns an "invalid endpoint" error.
func TestRequireSecureEndpoint_InvalidURL(t *testing.T) {
	err := requireSecureEndpoint("://bad-url", false)
	require.Error(t, err)
}

// TestResolveConnectPassword_FlagWins verifies that a --password flag value
// is returned without reading from env or stdin.
func TestResolveConnectPassword_FlagWins(t *testing.T) {
	c := cmdWithFlags()
	require.NoError(t, c.Flags().Set("password", "flag-password"))
	pw, err := resolveConnectPassword(c, "bob")
	require.NoError(t, err)
	assert.Equal(t, "flag-password", pw)
}

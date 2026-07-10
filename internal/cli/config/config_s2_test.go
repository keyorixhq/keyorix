// config_s2_test.go — coverage sprint 2 for internal/cli/config.
// Targets: CLIConfig methods (GetAPIKey, GetMode, IsEmbeddedMode, IsClientMode,
// GetTimeout, SetEmbeddedMode, AddConnection, RemoveConnection, GetConnection,
// GetDefaultConnection, SetActiveProject, GetActiveProject, getDefaultCLIConfigPath,
// GetConfigPath) plus gaps in runTestConnection and LoadCLIConfig.
package config

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────── AuthConfig.GetAPIKey ────────────────────────────

func TestGetAPIKey_PrefersEnvVar(t *testing.T) {
	t.Setenv("KEYORIX_API_KEY", "env-key")
	a := &AuthConfig{APIKey: "file-key"}
	assert.Equal(t, "env-key", a.GetAPIKey())
}

func TestGetAPIKey_FallsBackToField(t *testing.T) {
	t.Setenv("KEYORIX_API_KEY", "")
	a := &AuthConfig{APIKey: "file-key"}
	assert.Equal(t, "file-key", a.GetAPIKey())
}

// ──────────────────────────── CLIConfig mode helpers ─────────────────────────

func TestGetMode(t *testing.T) {
	c := &CLIConfig{Mode: "client"}
	assert.Equal(t, "client", c.GetMode())
}

func TestIsEmbeddedMode_True(t *testing.T) {
	c := &CLIConfig{Mode: "embedded"}
	assert.True(t, c.IsEmbeddedMode())
}

func TestIsEmbeddedMode_EmptyString(t *testing.T) {
	c := &CLIConfig{Mode: ""}
	assert.True(t, c.IsEmbeddedMode())
}

func TestIsEmbeddedMode_False(t *testing.T) {
	c := &CLIConfig{Mode: "client"}
	assert.False(t, c.IsEmbeddedMode())
}

func TestIsClientMode_True(t *testing.T) {
	c := &CLIConfig{Mode: "client"}
	assert.True(t, c.IsClientMode())
}

func TestIsClientMode_False(t *testing.T) {
	c := &CLIConfig{Mode: "embedded"}
	assert.False(t, c.IsClientMode())
}

// ──────────────────────────── GetTimeout ─────────────────────────────────────

func TestGetTimeout_Default(t *testing.T) {
	c := &CLIConfig{}
	assert.Equal(t, 30*time.Second, c.GetTimeout())
}

func TestGetTimeout_Parsed(t *testing.T) {
	c := &CLIConfig{Client: ClientConfig{Timeout: "10s"}}
	assert.Equal(t, 10*time.Second, c.GetTimeout())
}

func TestGetTimeout_Invalid(t *testing.T) {
	c := &CLIConfig{Client: ClientConfig{Timeout: "notaduration"}}
	assert.Equal(t, 30*time.Second, c.GetTimeout())
}

// ──────────────────────────── SetEmbeddedMode ────────────────────────────────

func TestSetEmbeddedMode(t *testing.T) {
	c := &CLIConfig{Mode: "client"}
	c.SetEmbeddedMode()
	assert.Equal(t, "embedded", c.Mode)
}

// ──────────────────────────── Connection management ──────────────────────────

func TestAddConnection_NewEntry(t *testing.T) {
	c := DefaultCLIConfig()
	c.AddConnection("prod", "https://prod.example.com", "key123", true)
	require.Len(t, c.Connections, 1)
	assert.Equal(t, "prod", c.Connections[0].Name)
	assert.True(t, c.Connections[0].Default)
}

func TestAddConnection_ReplacesExisting(t *testing.T) {
	c := DefaultCLIConfig()
	c.AddConnection("prod", "https://old.example.com", "", false)
	c.AddConnection("prod", "https://new.example.com", "k", true)
	// Should replace, not duplicate.
	assert.Len(t, c.Connections, 1)
	assert.Equal(t, "https://new.example.com", c.Connections[0].Endpoint)
}

func TestAddConnection_ClearsOtherDefaults(t *testing.T) {
	c := DefaultCLIConfig()
	c.AddConnection("a", "https://a.example.com", "", true)
	c.AddConnection("b", "https://b.example.com", "", true)
	// "a" must no longer be the default.
	conn, err := c.GetConnection("a")
	require.NoError(t, err)
	assert.False(t, conn.Default)
}

func TestAddConnection_NoAPIKey_TypeNone(t *testing.T) {
	c := DefaultCLIConfig()
	c.AddConnection("dev", "https://dev.example.com", "", false)
	require.Len(t, c.Connections, 1)
	assert.Equal(t, "none", c.Connections[0].Auth.Type)
}

func TestRemoveConnection_Existing(t *testing.T) {
	c := DefaultCLIConfig()
	c.AddConnection("prod", "https://prod.example.com", "k", false)
	c.RemoveConnection("prod")
	assert.Empty(t, c.Connections)
}

func TestRemoveConnection_NotFound_NoOp(t *testing.T) {
	c := DefaultCLIConfig()
	// Must not panic when name is absent.
	c.RemoveConnection("ghost")
	assert.Empty(t, c.Connections)
}

func TestGetConnection_Found(t *testing.T) {
	c := DefaultCLIConfig()
	c.AddConnection("prod", "https://prod.example.com", "k", false)
	conn, err := c.GetConnection("prod")
	require.NoError(t, err)
	assert.Equal(t, "https://prod.example.com", conn.Endpoint)
}

func TestGetConnection_NotFound(t *testing.T) {
	c := DefaultCLIConfig()
	_, err := c.GetConnection("ghost")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ghost")
}

func TestGetDefaultConnection_Set(t *testing.T) {
	c := DefaultCLIConfig()
	c.AddConnection("prod", "https://prod.example.com", "k", true)
	def := c.GetDefaultConnection()
	require.NotNil(t, def)
	assert.Equal(t, "prod", def.Name)
}

func TestGetDefaultConnection_None(t *testing.T) {
	c := DefaultCLIConfig()
	assert.Nil(t, c.GetDefaultConnection())
}

// ──────────────────────────── Active project ─────────────────────────────────

func TestSetGetActiveProject(t *testing.T) {
	c := DefaultCLIConfig()
	c.SetActiveProject("myproject")
	assert.Equal(t, "myproject", c.GetActiveProject())
}

// ──────────────────────────── getDefaultCLIConfigPath / GetConfigPath ────────

func TestGetConfigPath_XDG(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	p := getDefaultCLIConfigPath()
	assert.Equal(t, filepath.Join(dir, "keyorix", "cli.yaml"), p)
}

func TestGetConfigPath_NonEmpty(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	p := GetConfigPath()
	// Must be a non-empty string ending with expected tail.
	assert.NotEmpty(t, p)
}

// ──────────────────────────── LoadCLIConfig ──────────────────────────────────

func TestLoadCLIConfig_DefaultsWhenMissing(t *testing.T) {
	cfg, err := LoadCLIConfig(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	require.NoError(t, err)
	assert.Equal(t, "embedded", cfg.Mode)
}

func TestLoadCLIConfig_ParsesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cli.yaml")
	yaml := "mode: client\nclient:\n  endpoint: https://example.com\n  timeout: 60s\n"
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0600))

	cfg, err := LoadCLIConfig(path)
	require.NoError(t, err)
	assert.Equal(t, "client", cfg.Mode)
	assert.Equal(t, "https://example.com", cfg.Client.Endpoint)
}

func TestLoadCLIConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(path, []byte(":\tbad:yaml:[\n"), 0600))
	_, err := LoadCLIConfig(path)
	require.Error(t, err)
}

func TestLoadCLIConfig_DefaultsWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yaml")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0600))
	cfg, err := LoadCLIConfig(path)
	require.NoError(t, err)
	assert.Equal(t, "embedded", cfg.Mode)
	assert.Equal(t, "30s", cfg.Client.Timeout)
	assert.Equal(t, "./secrets.db", cfg.Embedded.DatabasePath)
}

func TestLoadCLIConfig_EmptyPath_UsesDefault(t *testing.T) {
	// With empty path it calls getDefaultCLIConfigPath; if the file doesn't exist,
	// returns defaults — no error.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	cfg, err := LoadCLIConfig("")
	require.NoError(t, err)
	assert.Equal(t, "embedded", cfg.Mode)
}

// ──────────────────────────── runTestConnection remote + 401 ─────────────────

func TestRunTestConnection_Remote_Reachable401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	t.Chdir(dir)
	yaml := "storage:\n  type: remote\n  remote:\n    base_url: " + srv.URL + "\n    timeout_seconds: 5\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(yaml), 0600))

	err := runTestConnection(testConnectionCmd, nil)
	require.NoError(t, err) // 401 means server is reachable
}

func TestRunTestConnection_Remote_Reachable200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	t.Chdir(dir)
	yaml := "storage:\n  type: remote\n  remote:\n    base_url: " + srv.URL + "\n    timeout_seconds: 5\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(yaml), 0600))

	err := runTestConnection(testConnectionCmd, nil)
	require.NoError(t, err)
}

func TestRunTestConnection_Remote_Unreachable(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	yaml := "storage:\n  type: remote\n  remote:\n    base_url: http://127.0.0.1:1\n    timeout_seconds: 1\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(yaml), 0600))

	err := runTestConnection(testConnectionCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not reach remote server")
}

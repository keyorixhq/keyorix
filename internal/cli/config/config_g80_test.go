// config_g80_test.go — closes remaining coverage gaps in internal/cli/config
// after prior sprints (s2/s26/extra/remote/conn/api_key/cleartext_warning).
//
// Gaps targeted:
//   - warnIfInsecureRemoteURL: empty raw, loopback-hostname short-circuits
//     (localhost/127.x/::1), and the net.ParseIP loopback fallback for an
//     IPv6 loopback literal not caught by the string checks.
//   - refuseConfigRedirect: never invoked by any existing test.
//   - runSetRemote / runUseLocal: config.Save failure branch, and reusing
//     an already-loaded config (existing Remote block / existing DB path).
//   - runTestConnection: config.Load failure branch.
//   - SetClientMode: apiKey == "" branch (Auth.Type == "none").
//   - SaveCLIConfig: empty configPath (uses default) and MkdirAll failure.
//   - LoadCLIConfig: os.ReadFile failure (path is a directory).
//   - getDefaultCLIConfigPath: last-resort branch when both XDG_CONFIG_HOME
//     and os.UserHomeDir() are unavailable.
package config

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ──────────────────────────── warnIfInsecureRemoteURL ────────────────────────

func TestWarnIfInsecureRemoteURL_EmptyRaw_NoOutput(t *testing.T) {
	out := captureStderr(t, func() {
		warnIfInsecureRemoteURL("")
	})
	assert.Empty(t, out, "empty URL must not produce a warning")
}

func TestWarnIfInsecureRemoteURL_LoopbackHostnames_NoOutput(t *testing.T) {
	for _, raw := range []string{
		"http://localhost/",
		"http://127.0.0.1:8080/",
		"http://[::1]/",
	} {
		t.Run(raw, func(t *testing.T) {
			out := captureStderr(t, func() {
				warnIfInsecureRemoteURL(raw)
			})
			assert.Empty(t, out, "loopback host %q must not warn", raw)
		})
	}
}

// TestWarnIfInsecureRemoteURL_LoopbackIPLiteral_NoOutput exercises the
// net.ParseIP(...).IsLoopback() fallback specifically: an IPv6 loopback
// literal spelled out in full does not match any of the string-prefix
// short-circuits (localhost / "127." / "::1") but must still be recognized
// as loopback and suppress the warning.
func TestWarnIfInsecureRemoteURL_LoopbackIPLiteral_NoOutput(t *testing.T) {
	raw := "http://[0:0:0:0:0:0:0:1]/"
	out := captureStderr(t, func() {
		warnIfInsecureRemoteURL(raw)
	})
	assert.Empty(t, out, "full-form IPv6 loopback literal must not warn")
}

// ──────────────────────────── refuseConfigRedirect ────────────────────────────

func TestRefuseConfigRedirect_ReturnsErrorNamingTarget(t *testing.T) {
	req := &http.Request{URL: &url.URL{Scheme: "https", Host: "evil.example.com", Path: "/redirected"}}
	err := refuseConfigRedirect(req, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "evil.example.com")
	assert.Contains(t, err.Error(), "refusing to follow redirect")
}

// ──────────────────────────── runSetRemote / runUseLocal gaps ────────────────

// TestRunSetRemote_SaveConfigError: a directory already occupies the
// "keyorix.yaml" path in the CWD, so config.Load fails to read it. #1644:
// this is neither "no config file" (IsNotExist) nor a case Load should ever
// silently paper over, so the command must fail at the LOAD step, before
// ever attempting to write anything — not fail later at the save step, as it
// did before that fix (proceed on any Load error, then fail trying to write
// through the directory).
func TestRunSetRemote_SaveConfigError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.Mkdir(filepath.Join(dir, "keyorix.yaml"), 0750))

	cmd := newSetRemoteCmd("https://keyorix.example.com", "")
	err := runSetRemote(cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load existing configuration")
}

func TestRunUseLocal_SaveConfigError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	require.NoError(t, os.Mkdir(filepath.Join(dir, "keyorix.yaml"), 0750))

	cmd := &cobra.Command{}
	err := runUseLocal(cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load existing configuration")
}

// TestRunSetRemote_ReusesExistingRemoteConfig covers the case where
// config.Load succeeds AND the loaded config already has a non-nil
// Storage.Remote block, so runSetRemote must reuse (not replace) it while
// still overwriting the fields it owns.
func TestRunSetRemote_ReusesExistingRemoteConfig(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	yaml := "storage:\n  type: remote\n  remote:\n    base_url: https://old.example.com\n    timeout_seconds: 5\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(yaml), 0600))

	cmd := newSetRemoteCmd("https://new.example.com", "")
	t.Setenv("KEYORIX_API_KEY", "")
	require.NoError(t, runSetRemote(cmd, nil))

	data, err := os.ReadFile(filepath.Join(dir, "keyorix.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "https://new.example.com")
	assert.NotContains(t, string(data), "old.example.com")
}

// TestRunUseLocal_PreservesExistingDBPath covers the branch where a config
// already on disk has a non-empty Storage.Database.Path: runUseLocal must
// leave that path alone rather than overwriting it with the "./secrets.db"
// default.
func TestRunUseLocal_PreservesExistingDBPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	yaml := "storage:\n  type: remote\n  database:\n    path: /custom/my.db\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keyorix.yaml"), []byte(yaml), 0600))

	cmd := &cobra.Command{}
	require.NoError(t, runUseLocal(cmd, nil))

	data, err := os.ReadFile(filepath.Join(dir, "keyorix.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "/custom/my.db", "existing DB path must be preserved, not reset to the default")
}

// ──────────────────────────── runTestConnection gap ───────────────────────────

func TestRunTestConnection_LoadConfigError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	// No keyorix.yaml present — config.Load fails.
	cmd := &cobra.Command{}
	err := runTestConnection(cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load configuration")
}

// ──────────────────────────── SetClientMode gap ───────────────────────────────

func TestSetClientMode_EmptyAPIKey_TypeNone(t *testing.T) {
	c := DefaultCLIConfig()
	c.SetClientMode("https://keyorix.example.com", "")
	assert.Equal(t, "none", c.Client.Auth.Type)
	assert.Empty(t, c.Client.Auth.APIKey)
}

// ──────────────────────────── SaveCLIConfig gaps ──────────────────────────────

func TestSaveCLIConfig_EmptyPath_UsesDefault(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	cfg := DefaultCLIConfig()
	require.NoError(t, SaveCLIConfig(cfg, ""))

	expected := filepath.Join(dir, "keyorix", "cli.yaml")
	_, err := os.Stat(expected)
	assert.NoError(t, err, "SaveCLIConfig with an empty path should write to the default location")
}

// TestSaveCLIConfig_MkdirAllError exercises the os.MkdirAll error branch: a
// regular file occupies a path component that needs to become a directory.
func TestSaveCLIConfig_MkdirAllError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))

	path := filepath.Join(blocker, "sub", "cli.yaml")
	cfg := DefaultCLIConfig()
	err := SaveCLIConfig(cfg, path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create config directory")
}

// ──────────────────────────── LoadCLIConfig gap ───────────────────────────────

// TestLoadCLIConfig_ReadFileError exercises the os.ReadFile error branch: the
// config path exists (so the os.IsNotExist short-circuit is skipped) but is a
// directory, so the read itself fails.
func TestLoadCLIConfig_ReadFileError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cli.yaml")
	require.NoError(t, os.Mkdir(path, 0750))

	_, err := LoadCLIConfig(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")
}

// ──────────────────────────── getDefaultCLIConfigPath gap ────────────────────

// TestGetDefaultCLIConfigPath_LastResort exercises the final fallback branch:
// neither XDG_CONFIG_HOME nor a resolvable home directory is available.
func TestGetDefaultCLIConfigPath_LastResort(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")
	if _, err := os.UserHomeDir(); err == nil {
		t.Skip("os.UserHomeDir() still resolves on this platform even with HOME unset; last-resort branch not reachable here")
	}
	assert.Equal(t, "./keyorix-cli.yaml", getDefaultCLIConfigPath())
}

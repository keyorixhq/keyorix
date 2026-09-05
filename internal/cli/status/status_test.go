package status

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

// chdirLocalConfig writes a local keyorix.yaml in a temp dir and chdirs there, so
// both the status display (config.Load("keyorix.yaml")) and InitializeCoreService
// (config.Load("")) resolve the same local backend.
func chdirLocalConfig(t *testing.T) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	require.NoError(t, config.Save("keyorix.yaml", &config.Config{
		Locale:  config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
		Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: filepath.Join(dir, "s.db")}},
	}))
}

func TestRunStatus_LocalHealthy(t *testing.T) {
	chdirLocalConfig(t)
	out := captureStdout(t, func() { require.NoError(t, runStatus(nil, nil)) })
	assert.Contains(t, out, "System Status")
	assert.Contains(t, out, "Storage Type: 💾 Local")
	assert.Contains(t, out, "Healthy")
}

func TestRunStatus_NoConfigUsesDefaults(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	dir := t.TempDir()
	t.Chdir(dir) // no keyorix.yaml present
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	out := captureStdout(t, func() { require.NoError(t, runStatus(nil, nil)) })
	assert.Contains(t, out, "No configuration found, using defaults")
	assert.Contains(t, out, "Storage Type: 💾 Local")
}

func TestRunPing_LocalRejected(t *testing.T) {
	chdirLocalConfig(t)
	err := runPing(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ping command only works with remote storage")
}

func TestRunPing_NoConfig(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // no keyorix.yaml
	err := runPing(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load configuration")
}

// TestRunStatus_RespectsConfigPathEnvVar is G80 Wave 0c's regression test for
// the runStatus config-load bug: it used to call config.Load("keyorix.yaml")
// with a hardcoded literal, so it never looked at KEYORIX_CONFIG_PATH — the
// same env var common.InitializeCoreService() (called two lines later, for the
// actual health check) DOES respect. Under a container/env-var-configured
// deployment (no literal ./keyorix.yaml in the CWD), the display fell through
// to "No configuration found, using defaults" / "Storage Type: Local" while
// the health check right below it silently ran against the REAL configured
// backend — the two could disagree about what storage type was even in use.
// This test points KEYORIX_CONFIG_PATH at a config file that is NOT named
// keyorix.yaml, in a directory with no keyorix.yaml either, so only a fix that
// actually reads the env var can pass. Confirmed red before the fix (asserted
// "No configuration found" / "Local" instead), green after.
func TestRunStatus_RespectsConfigPathEnvVar(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	cfgPath := filepath.Join(dir, "not-keyorix.yaml")
	require.NoError(t, config.Save(cfgPath, &config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
		Storage: config.StorageConfig{
			Type: "remote",
			Remote: &config.RemoteConfig{
				BaseURL:        "http://127.0.0.1:1", // unreachable on purpose — display-only assertion
				APIKey:         "test-key",
				TimeoutSeconds: 1,
				RetryAttempts:  1,
			},
		},
	}))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	var runErr error
	out := captureStdout(t, func() { runErr = runStatus(nil, nil) })
	var exitErr *common.ExitCodeError
	require.ErrorAs(t, runErr, &exitErr)
	assert.Equal(t, 1, exitErr.Code)
	assert.Contains(t, out, "Storage Type: 🌐 Remote")
	assert.Contains(t, out, "Server URL:   http://127.0.0.1:1")
	assert.NotContains(t, out, "No configuration found")
}

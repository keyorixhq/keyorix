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
// (config.Load("")) resolve the same local backend. Also pre-creates the database
// file via one InitializeCoreService call, simulating a deployment that has
// already been provisioned -- runStatus's own local-storage branch now verifies
// an existing store rather than provisioning one (#G-status-no-implicit-local),
// so a test asserting "Healthy" must hand it a store that already exists.
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
	_, err := common.InitializeCoreService()
	require.NoError(t, err)
}

func TestRunStatus_LocalHealthy(t *testing.T) {
	chdirLocalConfig(t)
	out := captureStdout(t, func() { require.NoError(t, runStatus(nil, nil)) })
	assert.Contains(t, out, "System Status")
	assert.Contains(t, out, "Storage Type: 💾 Local")
	assert.Contains(t, out, "Healthy")
}

// TestRunStatus_NoConfig_ReportsUnconfigured is the corrected replacement for
// the old TestRunStatus_NoConfigUsesDefaults, whose name described the actual
// defect: with zero configuration anywhere (no keyorix.yaml, no
// KEYORIX_CONFIG_PATH, no `keyorix connect`/env-var remote target), runStatus
// used to construct an in-memory storage.type: local config on the spot and
// run the normal InitializeCoreService() path against it -- which, for a
// brand-new "./secrets.db" path, CREATES the file, then reports "Healthy" for
// a database this very command just created. That is a false-success
// pattern, not a graceful default: the health check can never fail, because
// the thing being checked did not exist a moment before the check ran.
//
// The corrected contract: "not configured" is a first-class state, distinct
// from "unhealthy". runStatus must construct nothing and create nothing, and
// exit 2 (usage/config error) -- a caller chaining `keyorix status && deploy`
// must not proceed on an unconfigured machine. Asserted here by pointing the
// CLI at an empty temp dir and confirming it stays EMPTY after the call --
// the only assertion that actually distinguishes "correctly did nothing"
// from "silently did something and got lucky".
func TestRunStatus_NoConfig_ReportsUnconfigured(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	dir := t.TempDir()
	t.Chdir(dir) // no keyorix.yaml present
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	var runErr error
	out := captureStdout(t, func() { runErr = runStatus(nil, nil) })

	var exitErr *common.ExitCodeError
	require.ErrorAs(t, runErr, &exitErr)
	assert.Equal(t, 2, exitErr.Code)
	assert.Contains(t, out, "Not configured")
	assert.NotContains(t, out, "Healthy")
	assert.NotContains(t, out, "using defaults")

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "runStatus must create nothing on the no-config path; found: %v", entries)
}

// TestRunStatus_ExplicitLocalMissingFile covers the other half of
// #G-status-no-implicit-local: unlike the no-config case, a keyorix.yaml
// explicitly naming a local database IS present here, but the file itself
// does not exist yet. runStatus must report this as unhealthy (exit 1, not
// 2 -- the configuration itself is valid and complete, only the backend it
// names isn't there) and, critically, must not create the file while
// checking it.
func TestRunStatus_ExplicitLocalMissingFile(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	dbPath := filepath.Join(dir, "s.db")
	require.NoError(t, config.Save("keyorix.yaml", &config.Config{
		Locale:  config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
		Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: dbPath}},
	}))

	var runErr error
	out := captureStdout(t, func() { runErr = runStatus(nil, nil) })

	var exitErr *common.ExitCodeError
	require.ErrorAs(t, runErr, &exitErr)
	assert.Equal(t, 1, exitErr.Code)
	assert.Contains(t, out, "Storage Type: 💾 Local")
	assert.Contains(t, out, "does not exist")

	_, statErr := os.Stat(dbPath)
	assert.True(t, os.IsNotExist(statErr), "runStatus must not create the database file while checking it")
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
	assert.NotContains(t, out, "Not configured")
}

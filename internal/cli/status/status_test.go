package status

import (
	"io"
	"os"
	"path/filepath"
	"testing"

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

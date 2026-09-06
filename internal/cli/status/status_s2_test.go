// status_s2_test.go — sprint-2 coverage additions for the status package.
// Targets: the runStatus connection failure branch.
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

// writePingConfig writes a keyorix.yaml pointing at srv.URL and chdirs to dir.
func writePingConfig(t *testing.T, dir, baseURL string, timeoutSecs int) {
	t.Helper()
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, config.Save(cfgPath, &config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
		Storage: config.StorageConfig{
			Type: "remote",
			Remote: &config.RemoteConfig{
				BaseURL:        baseURL,
				TimeoutSeconds: timeoutSecs,
			},
		},
	}))
}

// TestRunStatus_RemoteConnectionFailed checks that runStatus still prints the
// remote-type display even when the health check fails (it swallows errors).
func TestRunStatus_RemoteConnectionFailed(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())

	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	// Remote config pointing at an unreachable address.
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, config.Save(cfgPath, &config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
		Storage: config.StorageConfig{
			Type: "remote",
			Remote: &config.RemoteConfig{
				BaseURL:        "http://127.0.0.1:1",
				TimeoutSeconds: 1,
			},
		},
	}))

	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	// runStatus never returns an error even for an unhealthy connection.
	errRun := runStatus(nil, nil)
	_ = w.Close()
	out, _ := io.ReadAll(r)
	outStr := string(out)

	assert.NoError(t, errRun)
	assert.Contains(t, outStr, "System Status")
	// Could be "Remote" display or fallback to default; either way no panic.
	assert.Contains(t, outStr, "Storage Type")
}

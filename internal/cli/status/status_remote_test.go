// status_remote_test.go — additional coverage for the status package.
// The existing status_test.go already covers runStatus (local). This file
// covers remaining uncovered paths in runStatus (remote display).
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

// ──────────────────────────── runStatus (remote display) ───────────────────

// TestRunStatus_RemoteTypeDisplayed covers the "case remote:" branch in
// runStatus (the switch on cfg.Storage.Type).
func TestRunStatus_RemoteTypeDisplayed(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	// Write a keyorix.yaml with storage.type=remote so the switch hits "remote:"
	// We deliberately don't configure a real remote server, so InitializeCoreService
	// will succeed (the remote storage client falls back gracefully) or fail, but
	// the important thing is the "Storage Type: 🌐 Remote" branch is hit first.
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, config.Save(cfgPath, &config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
		Storage: config.StorageConfig{
			Type: "remote",
			Remote: &config.RemoteConfig{
				BaseURL:        "http://127.0.0.1:0", // nothing listening, but parses OK
				TimeoutSeconds: 1,
			},
		},
	}))

	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	// runStatus never returns an error (it prints and swallows); we just check output.
	_ = runStatus(nil, nil)
	_ = w.Close()
	out, _ := io.ReadAll(r)

	assert.Contains(t, string(out), "System Status")
	assert.Contains(t, string(out), "Storage Type: 🌐 Remote")
}

// TestStatusCmdRegistered verifies StatusCmd is exported and has the correct
// Use string.
func TestStatusCmdRegistered(t *testing.T) {
	assert.Equal(t, "status", StatusCmd.Use)
}

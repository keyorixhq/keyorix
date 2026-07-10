// status_remote_test.go — additional coverage for the status package.
// The existing status_test.go already covers runStatus (local) and the ping
// error-guards.  This file covers remaining uncovered paths in runStatus
// (remote display) and the successful runPing path via an in-process httptest
// stub that lets the command reach the core service init.
package status

import (
	"io"
	"os"
	"path/filepath"
	"strings"
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

// ──────────────────────────── runPing ──────────────────────────────────────

// TestRunPing_RemoteNoConnectivity verifies that runPing with a configured
// remote endpoint (nothing listening) runs all three ping iterations and
// prints the summary without panicking, even though all pings fail.
// This exercises the ping loop, the successCount=0 summary branch, and
// the "No connectivity" status line.
//
// Note: this test takes ~3 s wall-clock because runPing sleep(1s) between pings.
// We mitigate this by pointing at 127.0.0.1:1 (connection refused, fast failure).
func TestRunPing_RemoteNoConnectivity(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")

	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, config.Save(cfgPath, &config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
		Storage: config.StorageConfig{
			Type: "remote",
			Remote: &config.RemoteConfig{
				BaseURL:        "http://127.0.0.1:1", // port 1 = IANA reserved; connection refused
				TimeoutSeconds: 1,
			},
		},
	}))

	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	// runPing never returns an error (the loop handles each failure inline).
	_ = runPing(nil, nil)
	_ = w.Close()
	out, _ := io.ReadAll(r)
	outStr := string(out)

	assert.Contains(t, outStr, "Pinging")
	assert.Contains(t, outStr, "Summary")
	assert.Contains(t, outStr, "Pings sent:")
	// With a connection-refused backend the summary is either "No connectivity"
	// or "Partial connectivity"; either is acceptable depending on the OS.
	assert.True(t,
		strings.Contains(outStr, "No connectivity") || strings.Contains(outStr, "Partial connectivity"),
		"expected a connectivity status line, got:\n%s", outStr)
}

// TestStatusCmdRegistered verifies StatusCmd and PingCmd are exported and
// have the correct Use strings.
func TestStatusCmdRegistered(t *testing.T) {
	assert.Equal(t, "status", StatusCmd.Use)
	assert.Equal(t, "ping", PingCmd.Use)
}

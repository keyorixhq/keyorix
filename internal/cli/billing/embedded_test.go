// embedded_test.go exercises runReport's dispatch branches — remote-mode
// selection via env, and the local/embedded storage path (storage-init
// failure, parseProjectIDs failure, and the unlicensed-feature error from
// core.GenerateBillingReport) — none of which billing_test.go's existing
// cases (which call runReportRemote/printBillingReport directly) drive.
package billing

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupEmbedded points KEYORIX_CONFIG_PATH at an isolated temp config in
// local (embedded SQLite) mode and clears remote env vars/XDG_CONFIG_HOME so
// common.NewRemoteClient() returns false and runReport takes the embedded
// path against a throwaway database, mirroring internal/cli/project's
// setupEmbedded helper.
func setupEmbedded(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, config.Save(cfgPath, &config.Config{
		Locale:  config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
		Storage: config.StorageConfig{Type: "local", Database: config.DatabaseConfig{Path: filepath.Join(dir, "test.db")}},
	}))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_SERVER", "")
}

func TestRunReport_Embedded_StorageInitError(t *testing.T) {
	resetFlags(t)
	dir := t.TempDir()
	// Points at a config file that does not exist, so config.Load (and thus
	// common.InitializeStorage) fails before any core/storage object is built.
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(dir, "nonexistent.yaml"))
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_SERVER", "")

	flagFrom = "2026-01-01T00:00:00Z"
	flagTo = "2026-02-01T00:00:00Z"
	flagProjectID = ""

	err := runReport(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

func TestRunReport_Embedded_ParseProjectIDsError(t *testing.T) {
	resetFlags(t)
	setupEmbedded(t)

	flagFrom = "2026-01-01T00:00:00Z"
	flagTo = "2026-02-01T00:00:00Z"
	flagProjectID = "not-a-number"

	err := runReport(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid project ID")
}

// TestRunReport_Embedded_Unlicensed drives runReport all the way through
// storage init, core construction, and parseProjectIDs success into
// core.GenerateBillingReport itself. The billing feature has no license gate
// wired for a bare CLI-constructed core, so it fails closed with a
// commercial-license error — this is the real, current behavior of running
// `keyorix billing report` embedded without a license, not a stand-in.
func TestRunReport_Embedded_Unlicensed(t *testing.T) {
	resetFlags(t)
	setupEmbedded(t)

	flagFrom = "2026-01-01T00:00:00Z"
	flagTo = "2026-02-01T00:00:00Z"
	flagProjectID = ""

	err := runReport(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to generate billing report")
	assert.Contains(t, err.Error(), "commercial license")
}

// TestRunReport_Remote_ViaEnv drives runReport's own remote-vs-embedded
// dispatch (the `if rc, ok := common.NewRemoteClient(); ok` branch), as
// opposed to the existing TestRunReportRemote_* cases which call
// runReportRemote directly and never exercise that selection.
func TestRunReport_Remote_ViaEnv(t *testing.T) {
	resetFlags(t)

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		env := map[string]interface{}{"data": sampleReport()}
		require.NoError(t, json.NewEncoder(w).Encode(env))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	flagFormat = "json"
	flagFrom = "2026-01-01T00:00:00Z"
	flagTo = "2026-02-01T00:00:00Z"
	flagProjectID = ""

	out, err := captureStdout(t, func() error { return runReport(nil, nil) })
	require.NoError(t, err)
	assert.Contains(t, out, "\"totals\"")
	assert.Equal(t, "/api/v1/admin/billing/report", gotPath)
}

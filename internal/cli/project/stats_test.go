package project

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupStatsRemote creates a mock HTTP server backed by handler, configures the
// KEYORIX_* env vars so common.NewRemoteClient returns true, and returns the
// RemoteClient plus a cleanup function.
func setupStatsRemote(t *testing.T, handler http.HandlerFunc) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	t.Setenv("KEYORIX_PROJECT", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(func() {
		statsFormat = "table"
	})
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close
}

// captureStatsStdout captures os.Stdout output from fn.
func captureStatsStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	require.NoError(t, w.Close())
	out, _ := io.ReadAll(r)
	return string(out)
}

// projectsAndStatsHandler serves /api/v1/projects and /api/v1/projects/1/stats
// in the standard sendSuccess envelope shape.
func projectsAndStatsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/projects":
		_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"acme","description":"test project"}]}}`))
	case "/api/v1/projects/1/stats":
		_, _ = w.Write([]byte(`{"success":true,"data":{` +
			`"project_id":1,` +
			`"project_name":"acme",` +
			`"total_secrets":42,` +
			`"active_secrets":39,` +
			`"expired_secrets":1,` +
			`"expiring_in_30_days":2,` +
			`"rotation_enabled":28,` +
			`"overdue_rotation":3,` +
			`"last_rotation_at":"2026-07-15T00:00:00Z",` +
			`"unique_accessors":7,` +
			`"open_anomalies":1,` +
			`"classification_counts":{"confidential":12,"internal":24,"public":3,"unclassified":3},` +
			`"computed_at":"2026-07-19T12:00:00Z"` +
			`}}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestProjectStats_Remote_TableFormat(t *testing.T) {
	rc, done := setupStatsRemote(t, projectsAndStatsHandler)
	defer done()

	statsFormat = "table"
	out := captureStatsStdout(t, func() {
		require.NoError(t, runStatsRemote(t.Context(), rc, "acme"))
	})

	// Header
	assert.Contains(t, out, "acme")

	// Secrets section
	assert.Contains(t, out, "Secrets")
	assert.Contains(t, out, "42")
	assert.Contains(t, out, "39")
	assert.Contains(t, out, "Expired")
	assert.Contains(t, out, "Expiring")

	// Rotation section
	assert.Contains(t, out, "Rotation")
	assert.Contains(t, out, "28")
	assert.Contains(t, out, "3")
	assert.Contains(t, out, "2026-07-15")

	// Access section
	assert.Contains(t, out, "Access")
	assert.Contains(t, out, "7")
	assert.Contains(t, out, "Open anomalies")

	// Classification section
	assert.Contains(t, out, "Classification")
	assert.Contains(t, out, "confidential")
	assert.Contains(t, out, "12")
	assert.Contains(t, out, "internal")
	assert.Contains(t, out, "24")
}

func TestProjectStats_Remote_JSONFormat(t *testing.T) {
	rc, done := setupStatsRemote(t, projectsAndStatsHandler)
	defer done()

	statsFormat = "json"
	out := captureStatsStdout(t, func() {
		require.NoError(t, runStatsRemote(t.Context(), rc, "acme"))
	})

	// Output must be valid JSON with the expected fields.
	assert.Contains(t, out, `"project_id":1`)
	assert.Contains(t, out, `"project_name":"acme"`)
	assert.Contains(t, out, `"total_secrets":42`)
	assert.Contains(t, out, `"active_secrets":39`)
	assert.Contains(t, out, `"expired_secrets":1`)
	assert.Contains(t, out, `"expiring_in_30_days":2`)
	assert.Contains(t, out, `"rotation_enabled":28`)
	assert.Contains(t, out, `"overdue_rotation":3`)
	assert.Contains(t, out, `"unique_accessors":7`)
	assert.Contains(t, out, `"open_anomalies":1`)
	assert.Contains(t, out, `"confidential":12`)
}

func TestProjectStats_Remote_NotFound(t *testing.T) {
	rc, done := setupStatsRemote(t, projectsAndStatsHandler)
	defer done()

	statsFormat = "table"
	err := runStatsRemote(t.Context(), rc, "nonexistent-project")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestProjectStats_Remote_UnsupportedFormat verifies the printStats default
// branch (format neither "table" nor "json") is rejected.
func TestProjectStats_Remote_UnsupportedFormat(t *testing.T) {
	rc, done := setupStatsRemote(t, projectsAndStatsHandler)
	defer done()

	statsFormat = "xml"
	err := runStatsRemote(t.Context(), rc, "acme")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported format")
}

// TestProjectStats_Remote_ListProjectsError verifies that a server error on
// GET /api/v1/projects is surfaced from runStatsRemote.
func TestProjectStats_Remote_ListProjectsError(t *testing.T) {
	rc, done := setupStatsRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer done()

	err := runStatsRemote(t.Context(), rc, "acme")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list projects")
}

// TestProjectStats_Remote_StatsEndpointError verifies that a server error on
// GET /api/v1/projects/{id}/stats is surfaced from runStatsRemote.
func TestProjectStats_Remote_StatsEndpointError(t *testing.T) {
	rc, done := setupStatsRemote(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"acme"}]}}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	defer done()

	err := runStatsRemote(t.Context(), rc, "acme")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get project stats")
}

// ── Embedded mode ────────────────────────────────────────────────────────

// setupStatsEmbedded configures an isolated on-disk SQLite database for the
// stats command in embedded mode (no KEYORIX_SERVER/TOKEN set).
func setupStatsEmbedded(t *testing.T) {
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
	t.Setenv("KEYORIX_PROJECT", "")
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(func() { statsFormat = "table" })
}

// TestProjectStats_Embedded_NotFound verifies runStatsEmbedded propagates the
// project-not-found error from common.LookupProjectIDByName.
func TestProjectStats_Embedded_NotFound(t *testing.T) {
	setupStatsEmbedded(t)

	err := runStatsEmbedded(context.Background(), "no-such-project")
	require.Error(t, err)
}

// TestProjectStats_Embedded_Table exercises the full embedded success path
// (InitializeCoreService, LookupProjectIDByName, GetProjectStats, table print).
func TestProjectStats_Embedded_Table(t *testing.T) {
	setupStatsEmbedded(t)

	createName = "alpha"
	createDescription = ""
	createEnvs = "dev"
	require.NoError(t, runCreate(nil, nil))
	t.Cleanup(func() { createName, createDescription, createEnvs = "", "", "" })

	statsFormat = "table"
	out := captureStatsStdout(t, func() {
		require.NoError(t, runStatsEmbedded(context.Background(), "alpha"))
	})
	assert.Contains(t, out, "Project: alpha")
	assert.Contains(t, out, "Secrets")
	assert.Contains(t, out, "Rotation")
	assert.Contains(t, out, "Access")
}

// TestProjectStats_Embedded_JSON exercises the embedded JSON-format branch.
func TestProjectStats_Embedded_JSON(t *testing.T) {
	setupStatsEmbedded(t)

	createName = "beta"
	createDescription = ""
	createEnvs = "prod"
	require.NoError(t, runCreate(nil, nil))
	t.Cleanup(func() { createName, createDescription, createEnvs = "", "", "" })

	statsFormat = "json"
	out := captureStatsStdout(t, func() {
		require.NoError(t, runStatsEmbedded(context.Background(), "beta"))
	})
	assert.Contains(t, out, `"project_name":"beta"`)
	assert.Contains(t, out, `"total_secrets"`)
}

// ── runStats dispatcher ─────────────────────────────────────────────────────

// TestProjectStats_RunE_Remote verifies statsCmd.RunE dispatches to the
// remote path when KEYORIX_SERVER + KEYORIX_TOKEN are set.
func TestProjectStats_RunE_Remote(t *testing.T) {
	_, done := setupStatsRemote(t, projectsAndStatsHandler)
	defer done()

	statsFormat = "table"
	out := captureStatsStdout(t, func() {
		require.NoError(t, statsCmd.RunE(statsCmd, []string{"acme"}))
	})
	assert.Contains(t, out, "acme")
}

// TestProjectStats_RunE_Embedded verifies statsCmd.RunE dispatches to the
// embedded path when no server env vars are set.
func TestProjectStats_RunE_Embedded(t *testing.T) {
	setupStatsEmbedded(t)

	err := statsCmd.RunE(statsCmd, []string{"no-such-project"})
	require.Error(t, err)
}

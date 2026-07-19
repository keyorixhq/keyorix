package project

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
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

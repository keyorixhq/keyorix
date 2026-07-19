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

// setupHealthRemote creates a mock HTTP server backed by handler, sets the
// KEYORIX_* env vars so common.NewRemoteClient returns true, and returns the
// client plus a cleanup function.
func setupHealthRemote(t *testing.T, handler http.HandlerFunc) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	t.Setenv("KEYORIX_PROJECT", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(func() {
		healthLimit = 20
		healthFormat = "table"
	})
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close
}

// captureHealthStdout captures os.Stdout output from fn.
func captureHealthStdout(t *testing.T, fn func()) string {
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

// projectsAndHealthHandler serves /api/v1/projects and /api/v1/projects/1/health
// in the real sendSuccess envelope shape.
func projectsAndHealthHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/projects":
		_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"web","description":"the web project"}]}}`))
	case "/api/v1/projects/1/health":
		_, _ = w.Write([]byte(`{"success":true,"data":{` +
			`"project_id":1,` +
			`"total_secrets":42,` +
			`"high_risk_count":3,` +
			`"medium_risk_count":11,` +
			`"low_risk_count":28,` +
			`"secrets":[` +
			`{"secret_id":5,"secret_name":"prod-db-password","score":91,"band":"high","factors":[{"key":"rotation","label":"Rotation age","score":100,"weight":0.3,"detail":"not rotated in 180 days"}]},` +
			`{"secret_id":8,"secret_name":"api-key-external","score":72,"band":"high","factors":[{"key":"exposure","label":"Exposure","score":90,"weight":0.2,"detail":"shared with 6 principals"}]},` +
			`{"secret_id":3,"secret_name":"stripe-webhook","score":68,"band":"medium","factors":[{"key":"expiry","label":"Expiry","score":40,"weight":0.3,"detail":"no expiry set"}]}` +
			`]}}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestProjectHealth_Remote_TableFormat(t *testing.T) {
	rc, done := setupHealthRemote(t, projectsAndHealthHandler)
	defer done()

	healthFormat = "table"
	out := captureHealthStdout(t, func() {
		require.NoError(t, runHealthRemote(t.Context(), rc, "web"))
	})

	// Header line with project and counts.
	assert.Contains(t, out, "web")
	assert.Contains(t, out, "42 secrets")
	assert.Contains(t, out, "3 HIGH")
	assert.Contains(t, out, "11 MEDIUM")
	assert.Contains(t, out, "28 LOW")

	// Table rows.
	assert.Contains(t, out, "prod-db-password")
	assert.Contains(t, out, "91")
	assert.Contains(t, out, "HIGH")
	assert.Contains(t, out, "api-key-external")
	assert.Contains(t, out, "stripe-webhook")
	assert.Contains(t, out, "MEDIUM")
}

func TestProjectHealth_Remote_JSONFormat(t *testing.T) {
	rc, done := setupHealthRemote(t, projectsAndHealthHandler)
	defer done()

	healthFormat = "json"
	out := captureHealthStdout(t, func() {
		require.NoError(t, runHealthRemote(t.Context(), rc, "web"))
	})

	// Output must be valid JSON containing the expected fields.
	assert.Contains(t, out, `"project_id":1`)
	assert.Contains(t, out, `"total_secrets":42`)
	assert.Contains(t, out, `"high_risk_count":3`)
	assert.Contains(t, out, `"medium_risk_count":11`)
	assert.Contains(t, out, `"low_risk_count":28`)
	assert.Contains(t, out, `"prod-db-password"`)
	assert.Contains(t, out, `"score":91`)
}

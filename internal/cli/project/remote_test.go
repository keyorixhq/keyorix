package project

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupRemote points the commands at a mock server via KEYORIX_SERVER/KEYORIX_TOKEN,
// so common.NewRemoteClient returns true and the remote code paths run. The handler
// returns responses in the REAL server envelope shape (sendSuccess: {"success":...,
// "data":<payload>}), so these tests exercise the exact wire contract.
func setupRemote(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	t.Setenv("KEYORIX_PROJECT", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(func() {
		createName, createDescription, createEnvs = "", "", ""
		envProjectFlag, envCreateName = "", ""
	})
}

// TestRunList_Remote drives `project list` in remote mode against the real
// sendSuccess envelope and asserts the returned project is actually printed. If the
// remote response struct double-wraps the {"data":…} envelope (which decodeEnvelope
// already strips), the project list decodes empty and this fails — surfacing that bug.
func TestRunList_Remote(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/projects", r.URL.Path)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"web","description":"the web project"}]}}`))
	})

	out := captureStdout(t, func() { require.NoError(t, runList(nil, nil)) })
	assert.Contains(t, out, "web", "remote project list must print the project returned by the server")
	assert.Contains(t, out, "the web project")
}

// projectsAndEnvsHandler serves the two endpoints the read commands hit, in the real
// sendSuccess envelope: a single project "web" (id=1) with two environments.
func projectsAndEnvsHandler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"web","description":"the web project"}]}}`))
		case "/api/v1/projects/1/environments":
			_, _ = w.Write([]byte(`{"success":true,"data":{"environments":[{"id":10,"name":"dev"},{"id":11,"name":"prod"}]}}`))
		default:
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestRunEnvironments_Remote(t *testing.T) {
	setupRemote(t, projectsAndEnvsHandler(t))
	out := captureStdout(t, func() { require.NoError(t, runEnvironments(nil, []string{"1"})) })
	assert.Contains(t, out, "dev")
	assert.Contains(t, out, "prod")
}

func TestRunEnvList_Remote(t *testing.T) {
	setupRemote(t, projectsAndEnvsHandler(t))
	envProjectFlag = "web" // resolveProjectContext resolves this to id=1 via the remote list
	out := captureStdout(t, func() { require.NoError(t, runEnvList(nil, nil)) })
	assert.Contains(t, out, `Environments for project "web":`)
	assert.Contains(t, out, "dev")
	assert.Contains(t, out, "prod")
}

func TestRunDescribe_Remote(t *testing.T) {
	setupRemote(t, projectsAndEnvsHandler(t))
	out := captureStdout(t, func() { require.NoError(t, runDescribe(nil, []string{"web"})) })
	assert.Contains(t, out, "Project:      web (id=1)")
	assert.Contains(t, out, "the web project")
	assert.Contains(t, out, "dev")
	assert.Contains(t, out, "prod")

	err := runDescribe(nil, []string{"ghost"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRunUse_Remote(t *testing.T) {
	setupRemote(t, projectsAndEnvsHandler(t))
	out := captureStdout(t, func() { require.NoError(t, runUse(nil, []string{"web"})) })
	assert.Contains(t, out, `Active project set to "web"`)

	err := runUse(nil, []string{"ghost"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

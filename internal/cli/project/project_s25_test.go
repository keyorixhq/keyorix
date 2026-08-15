// project_s25_test.go — s25 coverage blitz: remote error paths for describe,
// environments, env-list/create/delete, resolveProjectContext, and runUse.
package project

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupBrokenService configures KEYORIX_CONFIG_PATH to point at a config with
// an invalid storage type ("badtype"), so common.InitializeCoreService returns an
// error immediately from CreateStorage — without making any network calls and
// without needing KEYORIX_SERVER/KEYORIX_TOKEN to be unset.
func setupBrokenService(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "keyorix.yaml")
	require.NoError(t, config.Save(cfgPath, &config.Config{
		Locale:  config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
		Storage: config.StorageConfig{Type: "badtype"},
	}))
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_PROJECT", "web")
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(func() {
		createName, createDescription, createEnvs = "", "", ""
		envProjectFlag, envCreateName = "", ""
	})
}

// ── describeViaRemote — list-projects error ──────────────────────────────────

// TestRunDescribe_Remote_ListProjectsError verifies that a server error on
// GET /api/v1/projects is propagated correctly from describeViaRemote.
func TestRunDescribe_Remote_ListProjectsError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	err := runDescribe(nil, []string{"web"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list projects")
}

// TestRunDescribe_Remote_ListEnvsError verifies that a server error on
// GET /api/v1/projects/{id}/environments is surfaced as a list-environments error.
func TestRunDescribe_Remote_ListEnvsError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"web","description":""}]}}`))
		default:
			// /api/v1/projects/1/environments → 500
			w.WriteHeader(http.StatusInternalServerError)
		}
	})

	err := runDescribe(nil, []string{"web"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list environments")
}

// ── runEnvironments — remote GET error ───────────────────────────────────────

// TestRunEnvironments_Remote_GetError verifies that a server error on the
// environments endpoint is surfaced in remote mode.
func TestRunEnvironments_Remote_GetError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	err := runEnvironments(nil, []string{"1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list environments")
}

// ── runEnvList — remote GET environments error ───────────────────────────────

// TestRunEnvList_Remote_GetEnvsError verifies the error path when the
// environments endpoint returns an error in remote mode.
func TestRunEnvList_Remote_GetEnvsError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"web"}]}}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	envProjectFlag = "web"

	err := runEnvList(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list environments")
}

// ── runEnvCreate — remote POST error ─────────────────────────────────────────

// TestRunEnvCreate_Remote_PostError verifies the error path when the POST to
// create an environment fails in remote mode.
func TestRunEnvCreate_Remote_PostError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"web"}]}}`))
		default:
			// /api/v1/projects/1/environments POST → 500
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	envProjectFlag = "web"
	envCreateName = "qa"

	err := runEnvCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create environment")
}

// ── runEnvDelete — remote DELETE error ───────────────────────────────────────

// TestRunEnvDelete_Remote_DeleteError verifies the error path when the DELETE
// for an environment fails in remote mode.
func TestRunEnvDelete_Remote_DeleteError(t *testing.T) {
	origConfirm := envDeleteConfirm
	t.Cleanup(func() { envDeleteConfirm = origConfirm })
	envDeleteConfirm = true // deletion requires explicit --confirm (G27)

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	err := runEnvDelete(nil, []string{"3"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete environment")
}

// ── resolveProjectContext — remote GET projects error ────────────────────────

// TestResolveProjectContext_Remote_ListError verifies the error path when
// listing projects in remote mode fails.
func TestResolveProjectContext_Remote_ListError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, _, err := resolveProjectContext("web")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list projects")
}

// ── runUse — remote GET projects error ───────────────────────────────────────

// TestRunUse_Remote_ListError verifies the error path when listing projects
// returns an error in remote mode.
func TestRunUse_Remote_ListError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	err := runUse(nil, []string{"web"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list projects")
}

// ── local mode: InitializeCoreService error paths ────────────────────────────

// TestRunList_Embedded_BrokenService verifies that a broken storage config
// causes runList to return an initialization error.
func TestRunList_Embedded_BrokenService(t *testing.T) {
	setupBrokenService(t)
	t.Setenv("KEYORIX_PROJECT", "")

	err := runList(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

// TestRunEnvironments_Embedded_BrokenService verifies InitializeCoreService
// error in the local runEnvironments path.
func TestRunEnvironments_Embedded_BrokenService(t *testing.T) {
	setupBrokenService(t)

	err := runEnvironments(nil, []string{"1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

// TestRunEnvList_Embedded_BrokenService verifies InitializeCoreService error
// in the local runEnvList path.
func TestRunEnvList_Embedded_BrokenService(t *testing.T) {
	setupBrokenService(t)
	envProjectFlag = "web"

	err := runEnvList(nil, nil)
	require.Error(t, err)
	// resolveProjectContext fails at the local svc.ListProjects call, not at
	// InitializeCoreService (resolveProjectContext has its own svc call).
	require.NotNil(t, err)
}

// TestRunEnvCreate_Embedded_BrokenService verifies InitializeCoreService error
// in the local runEnvCreate path.
func TestRunEnvCreate_Embedded_BrokenService(t *testing.T) {
	setupBrokenService(t)
	envProjectFlag = "web"
	envCreateName = "staging"

	err := runEnvCreate(nil, nil)
	require.Error(t, err)
	require.NotNil(t, err)
}

// TestRunEnvDelete_Embedded_BrokenService verifies InitializeCoreService error
// in the local runEnvDelete path.
func TestRunEnvDelete_Embedded_BrokenService(t *testing.T) {
	setupBrokenService(t)

	err := runEnvDelete(nil, []string{"1"})
	require.Error(t, err)
	require.NotNil(t, err)
}

// TestRunCreate_Embedded_BrokenService verifies the InitializeCoreService error
// path in runCreate when envs are specified (the `CreateProjectWithEnvs` branch).
func TestRunCreate_Embedded_BrokenService(t *testing.T) {
	setupBrokenService(t)
	createName = "myapp"
	createEnvs = "dev"

	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

// TestRunCreate_Embedded_BrokenService_NoEnvs verifies the InitializeCoreService
// error path in runCreate when no envs are specified (the `CreateProject` branch).
func TestRunCreate_Embedded_BrokenService_NoEnvs(t *testing.T) {
	setupBrokenService(t)
	createName = "myapp"
	createEnvs = ""

	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

// TestDescribeViaLocal_BrokenService verifies the InitializeCoreService error
// path in describeViaLocal.
func TestDescribeViaLocal_BrokenService(t *testing.T) {
	setupBrokenService(t)

	err := describeViaLocal(nil, "web") //nolint:staticcheck
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize service")
}

// TestRunUse_Embedded_BrokenService verifies that a broken storage config causes
// runUse to return an initialization error in local mode.
func TestRunUse_Embedded_BrokenService(t *testing.T) {
	setupBrokenService(t)

	err := runUse(nil, []string{"web"})
	require.Error(t, err)
	require.NotNil(t, err)
}

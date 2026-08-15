// project_s2_test.go — sprint-2 coverage for the project CLI:
// runCreate (no envs / default / dup-name), runDescribe no-arg, remote
// env create/delete, and resolveProjectContext local project-not-found paths.
package project

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── runCreate – no-envs path ──────────────────────────────────────────────────

// TestRunCreate_Embedded_NoEnvs verifies that runCreate with no --envs flag
// goes through svc.CreateProject (not CreateProjectWithEnvs) and prints the
// default-environments message.
func TestRunCreate_Embedded_NoEnvs(t *testing.T) {
	setupEmbedded(t)
	createName = "backend"
	createEnvs = ""
	createDescription = "back-end service"

	out := captureStdout(t, func() { require.NoError(t, runCreate(nil, nil)) })
	assert.Contains(t, out, "Project created: id=")
	assert.Contains(t, out, `name="backend"`)
	assert.Contains(t, out, "Default environments")

	svc := embeddedCore(t)
	projects, err := svc.ListProjects(context.Background())
	require.NoError(t, err)
	require.Len(t, projects, 1)
	assert.Equal(t, "backend", projects[0].Name)
}

// TestRunCreate_Embedded_DupName verifies that creating two projects with the
// same name returns an error on the second attempt.
func TestRunCreate_Embedded_DupName(t *testing.T) {
	setupEmbedded(t)
	svc := embeddedCore(t)
	_, err := svc.CreateProject(context.Background(), "dupe", "")
	require.NoError(t, err)

	createName = "dupe"
	createEnvs = ""
	err = runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project")
}

// ── runDescribe – no-arg path ────────────────────────────────────────────────

// TestRunDescribe_Embedded_NoArgs verifies that runDescribe with no positional
// argument and no active project returns an error.
func TestRunDescribe_Embedded_NoArgs(t *testing.T) {
	setupEmbedded(t)
	err := runDescribe(nil, []string{})
	require.Error(t, err)
}

// TestRunDescribe_Embedded_NoArgs_WithEnv verifies that runDescribe picks up
// the active project from KEYORIX_PROJECT when no arg is given.
func TestRunDescribe_Embedded_NoArgs_WithEnv(t *testing.T) {
	setupEmbedded(t)
	_, err := embeddedCore(t).CreateProjectWithEnvs(context.Background(), "api", "the api", []string{"prod"})
	require.NoError(t, err)
	t.Setenv("KEYORIX_PROJECT", "api")

	out := captureStdout(t, func() { require.NoError(t, runDescribe(nil, []string{})) })
	assert.Contains(t, out, "Project:      api")
}

// ── resolveProjectContext – local project-not-found ───────────────────────────

// TestResolveProjectContext_LocalNotFound verifies that resolveProjectContext
// returns an error when the named project doesn't exist in the local store.
func TestResolveProjectContext_LocalNotFound(t *testing.T) {
	setupEmbedded(t)
	_, _, err := resolveProjectContext("myproj")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ── remote env create / delete ────────────────────────────────────────────────

// TestRunEnvCreate_Remote verifies the remote-mode env create path.
func TestRunEnvCreate_Remote(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"web"}]}}`))
		case "/api/v1/projects/1/environments":
			_, _ = w.Write([]byte(`{"success":true,"data":{"id":5,"name":"qa","project_id":1}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	envProjectFlag = "web"
	envCreateName = "qa"

	out := captureStdout(t, func() { require.NoError(t, runEnvCreate(nil, nil)) })
	assert.Contains(t, out, `"qa" created`)
}

// TestRunEnvDelete_Remote verifies the remote-mode env delete path.
func TestRunEnvDelete_Remote(t *testing.T) {
	origConfirm := envDeleteConfirm
	t.Cleanup(func() { envDeleteConfirm = origConfirm })
	envDeleteConfirm = true // deletion requires explicit --confirm (G27)

	var deleteCalled bool
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/api/v1/environments/3" {
			deleteCalled = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	out := captureStdout(t, func() { require.NoError(t, runEnvDelete(nil, []string{"3"})) })
	assert.True(t, deleteCalled)
	assert.Contains(t, out, "deleted")
}

// TestRunEnvList_Remote_Empty verifies the empty-environment message in remote mode.
func TestRunEnvList_Remote_Empty(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[{"id":1,"name":"web"}]}}`))
		case "/api/v1/projects/1/environments":
			_, _ = w.Write([]byte(`{"success":true,"data":{"environments":[]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	envProjectFlag = "web"

	out := captureStdout(t, func() { require.NoError(t, runEnvList(nil, nil)) })
	assert.Contains(t, out, "No environments")
}

// TestRunList_Remote_Empty verifies the "No projects found" message in remote mode.
func TestRunList_Remote_Empty(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"projects":[]}}`))
	})

	out := captureStdout(t, func() { require.NoError(t, runList(nil, nil)) })
	assert.Contains(t, out, "No projects found")
}

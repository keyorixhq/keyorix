// env_delete_test.go — CLI tests for the confirmation gate on
// `keyorix project env delete` (G27): mirrors the mandatory --confirm flag
// convention used by `notification channel delete` (no interactive prompt —
// a missing --confirm is a hard error and no mutation may occur).
package project

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvDeleteCmd_HasConfirmFlag(t *testing.T) {
	f := envDeleteCmd.Flags().Lookup("confirm")
	require.NotNil(t, f, "env delete must expose --confirm to require explicit confirmation")
	assert.Equal(t, "false", f.DefValue, "confirmation must be required by default")
}

func TestRunEnvDelete_NoConfirm_ErrorsAndNoAPICall(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origConfirm := envDeleteConfirm
	t.Cleanup(func() { envDeleteConfirm = origConfirm })
	envDeleteConfirm = false

	err := runEnvDelete(envDeleteCmd, []string{"10"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "add --confirm")
	assert.False(t, called, "API must not be called without --confirm")
}

func TestRunEnvDelete_Confirmed_CallsAPI(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/v1/environments/10", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origConfirm := envDeleteConfirm
	t.Cleanup(func() { envDeleteConfirm = origConfirm })
	envDeleteConfirm = true

	err := runEnvDelete(envDeleteCmd, []string{"10"})
	require.NoError(t, err)
	assert.True(t, called, "API must be called once --confirm is set")
}

func TestRunEnvDelete_InvalidID(t *testing.T) {
	origConfirm := envDeleteConfirm
	t.Cleanup(func() { envDeleteConfirm = origConfirm })
	envDeleteConfirm = true

	err := runEnvDelete(envDeleteCmd, []string{"not-a-number"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid environment ID")
}

// TestRunEnvDelete_ProjectMismatch_RefusedWithoutAPICall is the required
// regression case at the CLI layer: `env delete --project <name>` declares a
// project the operator believes environment 10 belongs to. Environment 10
// actually belongs to a DIFFERENT project (id 77) than the one the mock
// server returns for the named project's own environment list (which only
// contains id 20). The bare id alone can't reveal this mismatch, so the fix
// under test must look up the named project's environments and cross-check
// before ever issuing the DELETE — must be refused, and the DELETE endpoint
// must never be hit.
func TestRunEnvDelete_ProjectMismatch_RefusedWithoutAPICall(t *testing.T) {
	deleteCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":42,"name":"other-project"}]}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects/42/environments":
			// project 42's real environments do NOT include id 10 — the
			// operator's belief that env 10 belongs to "other-project" is wrong.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"environments":[{"id":20,"name":"prod","project_id":42}]}}`))
		case r.Method == http.MethodDelete:
			deleteCalled = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origConfirm := envDeleteConfirm
	origProject := envProjectFlag
	t.Cleanup(func() {
		envDeleteConfirm = origConfirm
		envProjectFlag = origProject
	})
	envDeleteConfirm = true
	envProjectFlag = "other-project"

	err := runEnvDelete(envDeleteCmd, []string{"10"})
	require.Error(t, err, "deleting an env id that doesn't belong to the named --project must be refused")
	assert.Contains(t, err.Error(), "does not belong to project")
	assert.False(t, deleteCalled, "DELETE must never be issued once the project cross-check fails")
}

// TestRunEnvDelete_ProjectMatch_CallsAPI is the positive counterpart: when
// --project correctly names the environment's actual owning project, the
// cross-check passes and the delete proceeds as before.
func TestRunEnvDelete_ProjectMatch_CallsAPI(t *testing.T) {
	deleteCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":42,"name":"other-project"}]}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects/42/environments":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"environments":[{"id":10,"name":"prod","project_id":42}]}}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/environments/10":
			deleteCalled = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origConfirm := envDeleteConfirm
	origProject := envProjectFlag
	t.Cleanup(func() {
		envDeleteConfirm = origConfirm
		envProjectFlag = origProject
	})
	envDeleteConfirm = true
	envProjectFlag = "other-project"

	err := runEnvDelete(envDeleteCmd, []string{"10"})
	require.NoError(t, err)
	assert.True(t, deleteCalled, "DELETE must be issued once the project cross-check passes")
}

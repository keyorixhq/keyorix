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

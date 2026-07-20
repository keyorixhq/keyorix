package system

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupRoleExpiryRemote(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
}

func setupRoleExpiryDisconnected(t *testing.T) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(dir, "nonexistent.yaml"))
}

func TestRoleExpiryCheckCmd_Success(t *testing.T) {
	setupRoleExpiryRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/admin/jobs/role-expiry-check", r.URL.Path)
		_, _ = w.Write([]byte(`{"data":{"warnings":3,"criticals":1}}`))
	})

	out := captureStdout(t, func() {
		require.NoError(t, roleExpiryCheckCmd.RunE(nil, nil))
	})
	assert.Contains(t, out, "3 warning(s)")
	assert.Contains(t, out, "1 critical(s)")
}

func TestRoleExpiryCheckCmd_ZeroResults(t *testing.T) {
	setupRoleExpiryRemote(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"warnings":0,"criticals":0}}`))
	})

	out := captureStdout(t, func() {
		require.NoError(t, roleExpiryCheckCmd.RunE(nil, nil))
	})
	assert.Contains(t, out, "0 warning(s)")
	assert.Contains(t, out, "0 critical(s)")
}

func TestRoleExpiryCheckCmd_ServerError(t *testing.T) {
	setupRoleExpiryRemote(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	err := roleExpiryCheckCmd.RunE(nil, nil)
	require.Error(t, err)
}

func TestRoleExpiryCheckCmd_NotConnected(t *testing.T) {
	setupRoleExpiryDisconnected(t)

	err := roleExpiryCheckCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

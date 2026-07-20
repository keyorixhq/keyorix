package system

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTokenExpiryRemote(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
}

func setupTokenExpiryDisconnected(t *testing.T) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(dir, "nonexistent.yaml"))
}

func TestTokenExpiryCheckCmd_Success(t *testing.T) {
	setupTokenExpiryRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/admin/jobs/token-expiry-check", r.URL.Path)
		_, _ = w.Write([]byte(`{"data":{"pat_warnings":2,"pat_criticals":1,"machine_warnings":3,"machine_criticals":0}}`))
	})

	out := captureStdout(t, func() {
		require.NoError(t, tokenExpiryCheckCmd.RunE(nil, nil))
	})
	assert.Contains(t, out, "2 PAT warning(s)")
	assert.Contains(t, out, "1 PAT critical(s)")
	assert.Contains(t, out, "3 machine warning(s)")
	assert.Contains(t, out, "0 machine critical(s)")
}

func TestTokenExpiryCheckCmd_ZeroResults(t *testing.T) {
	setupTokenExpiryRemote(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"pat_warnings":0,"pat_criticals":0,"machine_warnings":0,"machine_criticals":0}}`))
	})

	out := captureStdout(t, func() {
		require.NoError(t, tokenExpiryCheckCmd.RunE(nil, nil))
	})
	assert.Contains(t, out, "0 PAT warning(s)")
	assert.Contains(t, out, "0 PAT critical(s)")
}

func TestTokenExpiryCheckCmd_ServerError(t *testing.T) {
	setupTokenExpiryRemote(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	err := tokenExpiryCheckCmd.RunE(nil, nil)
	require.Error(t, err)
}

func TestTokenExpiryCheckCmd_NotConnected(t *testing.T) {
	setupTokenExpiryDisconnected(t)

	err := tokenExpiryCheckCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

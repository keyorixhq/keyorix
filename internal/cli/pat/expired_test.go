package pat

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const expiredTokensPayload = `{"data":[
	{"id":3,"name":"old-ci","token_prefix":"kx_pat_ab","created_at":"2026-01-01T00:00:00Z","expires_at":"2026-02-01T00:00:00Z"},
	{"id":7,"name":"stale-deploy","token_prefix":"kx_pat_cd","created_at":"2026-03-01T00:00:00Z","expires_at":"2026-04-01T00:00:00Z"}
]}`

func setupExpiredRemote(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
}

func setupExpiredDisconnected(t *testing.T) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
}

func TestListExpired_NotConnected(t *testing.T) {
	setupExpiredDisconnected(t)
	err := listExpiredCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestCleanupExpired_NotConnected(t *testing.T) {
	setupExpiredDisconnected(t)
	err := cleanupExpiredCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestListExpired_Empty(t *testing.T) {
	setupExpiredRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/auth/tokens/expired", r.URL.Path)
		_, _ = w.Write([]byte(`{"data":[]}`))
	})
	out := captureStdout(t, func() { require.NoError(t, listExpiredCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "no expired personal access tokens")
}

func TestListExpired_WithTokens(t *testing.T) {
	setupExpiredRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/auth/tokens/expired", r.URL.Path)
		_, _ = w.Write([]byte(expiredTokensPayload))
	})
	out := captureStdout(t, func() { require.NoError(t, listExpiredCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "old-ci")
	assert.Contains(t, out, "stale-deploy")
	assert.Contains(t, out, "NAME")
}

func TestListExpired_ServerError(t *testing.T) {
	setupExpiredRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"success":false,"error":"internal error"}`))
	})
	err := listExpiredCmd.RunE(nil, nil)
	require.Error(t, err)
}

func TestCleanupExpired_Success(t *testing.T) {
	setupExpiredRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/v1/auth/tokens/expired", r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	})
	out := captureStdout(t, func() { require.NoError(t, cleanupExpiredCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "revoked")
}

func TestCleanupExpired_ServerError(t *testing.T) {
	setupExpiredRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"success":false,"error":"internal error"}`))
	})
	err := cleanupExpiredCmd.RunE(nil, nil)
	require.Error(t, err)
}

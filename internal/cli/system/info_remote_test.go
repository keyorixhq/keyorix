package system

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func systemInfoStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/system/info" {
			_, _ = w.Write([]byte(`{"data":{"version":"v0.68.0","git_commit":"abc1234","go_version":"go1.26","os":"linux","arch":"amd64","uptime":"3h","environment":"production","features":{"tls_enabled":true,"grpc_enabled":false},"database":{"type":"postgres","connected":true},"security":{"tls_enabled":true,"auth_enabled":true,"encryption_method":"AES-256-GCM","audit_enabled":true}}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close
}

func TestFetchSystemInfo(t *testing.T) {
	rc, done := systemInfoStub(t)
	defer done()
	info, err := fetchSystemInfo(context.Background(), rc)
	require.NoError(t, err)
	assert.Equal(t, "v0.68.0", info.Version)
	assert.Equal(t, "abc1234", info.GitCommit)
	assert.Equal(t, "postgres", info.Database.Type)
	assert.True(t, info.Database.Connected)
	assert.Equal(t, "AES-256-GCM", info.Security.EncryptionMethod)
	assert.True(t, info.Features["tls_enabled"])
}

func TestFetchSystemInfo_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	c, ok := common.NewRemoteClient()
	require.True(t, ok)
	_, err := fetchSystemInfo(context.Background(), c)
	require.Error(t, err)
}

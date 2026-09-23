package secret

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRenderClient(t *testing.T, srv *httptest.Server) *common.RemoteClient {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc
}

func TestRenderRemote_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/projects/7/secrets/render", r.URL.Path)
		_, _ = w.Write([]byte(`{"data":{"rendered":"DB_PASSWORD=s3cr3t\nAPI_KEY=k3y\n"}}`))
	}))
	defer srv.Close()
	rc := newRenderClient(t, srv)

	out, err := renderRemote(context.Background(), rc, 7,
		"DB_PASSWORD=${secret:prod/db-password}\nAPI_KEY=${secret:prod/api-key}\n")
	require.NoError(t, err)
	assert.Equal(t, "DB_PASSWORD=s3cr3t\nAPI_KEY=k3y\n", out)
}

func TestRenderRemote_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()
	rc := newRenderClient(t, srv)

	_, err := renderRemote(context.Background(), rc, 7, "x=${secret:prod/nope}")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "render template")
}

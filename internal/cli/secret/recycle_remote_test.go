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

func recycleStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects/3/secrets/deleted":
			_, _ = w.Write([]byte(`{"data":{"deleted":[{"id":9,"name":"old-db","type":"password","classification":"confidential","deleted_at":"2026-06-18T12:00:00Z"},{"id":8,"name":"old-api","type":"token","classification":"","deleted_at":"2026-06-18T10:00:00Z"}],"total":2}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets/9/restore":
			_, _ = w.Write([]byte(`{"data":{"id":9,"restored":true},"message":"Secret restored"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close
}

func TestFetchTrash(t *testing.T) {
	rc, done := recycleStub(t)
	defer done()
	rows, err := fetchTrash(context.Background(), rc, 3, 0)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, uint(9), rows[0].ID, "newest-deleted first")
	assert.Equal(t, "old-db", rows[0].Name)
	assert.Equal(t, "confidential", rows[0].Classification)
	assert.Equal(t, "token", rows[1].Type)
}

func TestFetchTrash_NotFound(t *testing.T) {
	rc, done := recycleStub(t)
	defer done()
	_, err := fetchTrash(context.Background(), rc, 999, 0)
	require.Error(t, err)
}

func TestRestoreSecret(t *testing.T) {
	rc, done := recycleStub(t)
	defer done()
	require.NoError(t, restoreSecret(context.Background(), rc, 9))
}

func TestRestoreSecret_NotFound(t *testing.T) {
	rc, done := recycleStub(t)
	defer done()
	require.Error(t, restoreSecret(context.Background(), rc, 1))
}

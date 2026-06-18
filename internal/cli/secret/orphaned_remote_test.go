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

func orphanedStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects/4/secrets/orphaned":
			_, _ = w.Write([]byte(`{"data":{"orphaned":[{"id":11,"name":"ghost","type":"password","classification":"confidential","owner_id":99},{"id":12,"name":"orphan-a","type":"token","classification":"","owner_id":2}],"total":2}}`))
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

func TestFetchOrphaned(t *testing.T) {
	rc, done := orphanedStub(t)
	defer done()
	rows, err := fetchOrphaned(context.Background(), rc, 4)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, uint(11), rows[0].ID)
	assert.Equal(t, "ghost", rows[0].Name)
	assert.Equal(t, uint(99), rows[0].OwnerID)
	assert.Equal(t, "token", rows[1].Type)
}

func TestFetchOrphaned_NotFound(t *testing.T) {
	rc, done := orphanedStub(t)
	defer done()
	_, err := fetchOrphaned(context.Background(), rc, 999)
	require.Error(t, err)
}

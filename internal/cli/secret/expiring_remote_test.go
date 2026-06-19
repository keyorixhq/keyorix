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

func expiringStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/projects/4/secrets/expiring" {
			_, _ = w.Write([]byte(`{"data":{"expiring":[{"id":9,"name":"old-cert","type":"certificate","environment_id":2,"expiration":"2026-06-10T00:00:00Z","expired":true},{"id":8,"name":"api-key","type":"token","environment_id":2,"expiration":"2026-06-25T00:00:00Z","expired":false}],"total":2}}`))
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

func TestFetchExpiring(t *testing.T) {
	rc, done := expiringStub(t)
	defer done()
	rows, err := fetchExpiring(context.Background(), rc, 4, 30)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, uint(9), rows[0].ID)
	assert.True(t, rows[0].Expired)
	assert.Equal(t, "api-key", rows[1].Name)
	assert.False(t, rows[1].Expired)
}

func TestFetchExpiring_NotFound(t *testing.T) {
	rc, done := expiringStub(t)
	defer done()
	_, err := fetchExpiring(context.Background(), rc, 999, 0)
	require.Error(t, err)
}

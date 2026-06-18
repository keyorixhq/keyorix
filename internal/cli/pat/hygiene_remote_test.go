package pat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hygieneStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/pat-hygiene" {
			_, _ = w.Write([]byte(`{"data":{"tokens":[{"id":2,"name":"ci","token_prefix":"kx_pat_ci","user_id":7,"last_used_at":"","expired":false,"stale":true},{"id":5,"name":"old","token_prefix":"kx_pat_old","user_id":9,"expires_at":"2026-01-01T00:00:00Z","last_used_at":"2026-06-17T00:00:00Z","expired":true,"stale":false}],"total":2}}`))
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

func TestFetchPATHygiene(t *testing.T) {
	rc, done := hygieneStub(t)
	defer done()
	rows, err := fetchPATHygiene(context.Background(), rc, 30)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "ci", rows[0].Name)
	assert.True(t, rows[0].Stale)
	assert.False(t, rows[0].Expired)
	assert.Equal(t, uint(9), rows[1].UserID)
	assert.True(t, rows[1].Expired)
}

func TestFlagLabel(t *testing.T) {
	assert.Equal(t, "stale", flagLabel(hygieneRow{Stale: true}))
	assert.Equal(t, "expired", flagLabel(hygieneRow{Expired: true}))
	assert.Equal(t, "exp,stale", flagLabel(hygieneRow{Expired: true, Stale: true}))
}

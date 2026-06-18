package project

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
		if r.URL.Path == "/api/v1/projects/7/hygiene" {
			_, _ = w.Write([]byte(`{"data":{"orphaned_secrets":2,"unused_secrets":5,"expiring_secrets":1,"stale_machine_identities":3}}`))
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

func TestFetchHygiene(t *testing.T) {
	rc, done := hygieneStub(t)
	defer done()
	h, err := fetchHygiene(context.Background(), rc, 7)
	require.NoError(t, err)
	assert.Equal(t, 2, h.OrphanedSecrets)
	assert.Equal(t, 5, h.UnusedSecrets)
	assert.Equal(t, 1, h.ExpiringSecrets)
	assert.Equal(t, 3, h.StaleMachineIdentities)
}

func TestFetchHygiene_NotFound(t *testing.T) {
	rc, done := hygieneStub(t)
	defer done()
	_, err := fetchHygiene(context.Background(), rc, 999)
	require.Error(t, err)
}

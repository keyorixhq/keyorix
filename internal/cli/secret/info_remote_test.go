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

func infoStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/secrets/7":
			_, _ = w.Write([]byte(`{"data":{"ID":7,"Name":"db","Type":"password","Classification":"confidential","Status":"active","Description":"prod DB","OwnerID":3,"IsShared":true,"CreatedBy":"alice"}}`))
		case "/api/v1/secrets/7/tags":
			_, _ = w.Write([]byte(`{"data":{"tags":["prod","tier1"]}}`))
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

func TestFetchInfo(t *testing.T) {
	rc, done := infoStub(t)
	defer done()
	v, err := fetchInfo(context.Background(), rc, 7)
	require.NoError(t, err)
	assert.Equal(t, "db", v.Name)
	assert.Equal(t, "confidential", v.Classification)
	assert.Equal(t, uint(3), v.OwnerID)
	assert.True(t, v.IsShared)
	assert.Equal(t, "prod DB", v.Description)
}

func TestFetchInfo_NotFound(t *testing.T) {
	rc, done := infoStub(t)
	defer done()
	_, err := fetchInfo(context.Background(), rc, 999)
	require.Error(t, err)
}

func TestInfoHelpers(t *testing.T) {
	assert.Equal(t, "active", orDefault("", "active"))
	assert.Equal(t, "suspended", orDefault("suspended", "active"))
	assert.Equal(t, "yes", boolWord(true))
	assert.Equal(t, "no", boolWord(false))
}

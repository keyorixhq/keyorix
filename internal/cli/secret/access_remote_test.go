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

func accessStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/secrets/7/access":
			_, _ = w.Write([]byte(`{"data":{"accessors":[{"user_id":1,"username":"owner","permission":"owner","source":"owner"},{"user_id":2,"username":"alice","permission":"read","source":"group_share:platform"}],"total":2}}`))
		case "/api/v1/secrets/7/access-log":
			_, _ = w.Write([]byte(`{"data":{"access_log":[{"AccessedBy":"owner","Action":"read","IPAddress":"10.0.0.1","AccessTime":"2026-06-18T10:00:00Z"}],"total":1}}`))
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

func TestFetchAccessors(t *testing.T) {
	rc, done := accessStub(t)
	defer done()
	rows, err := fetchAccessors(context.Background(), rc, 7)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	assert.Equal(t, "owner", rows[0].Username)
	assert.Equal(t, "owner", rows[0].Permission)
	assert.Equal(t, "group_share:platform", rows[1].Source)
}

func TestFetchAccessLog(t *testing.T) {
	rc, done := accessStub(t)
	defer done()
	rows, err := fetchAccessLog(context.Background(), rc, 7, 30)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "owner", rows[0].AccessedBy)
	assert.Equal(t, "read", rows[0].Action)
	assert.Equal(t, "10.0.0.1", rows[0].IPAddress)
}

func TestFetchAccessors_NotFound(t *testing.T) {
	rc, done := accessStub(t)
	defer done()
	_, err := fetchAccessors(context.Background(), rc, 999)
	require.Error(t, err)
}

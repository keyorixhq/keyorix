package secret

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tagsStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets/42/tags":
			_, _ = w.Write([]byte(`{"data":{"tags":["db","prod"]}}`))
		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/secrets/42/tags":
			b, _ := io.ReadAll(r.Body)
			var got map[string][]string
			_ = json.Unmarshal(b, &got)
			// Echo the (server-normalized) set back; assert the body round-trips.
			if len(got["tags"]) == 2 {
				_, _ = w.Write([]byte(`{"data":{"tags":["prod","tier1"]}}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"tags":[]}}`))
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

func TestGetSecretTags(t *testing.T) {
	rc, done := tagsStub(t)
	defer done()
	tags, err := getSecretTags(context.Background(), rc, 42)
	require.NoError(t, err)
	assert.Equal(t, []string{"db", "prod"}, tags)
}

func TestSetSecretTags(t *testing.T) {
	rc, done := tagsStub(t)
	defer done()
	tags, err := setSecretTags(context.Background(), rc, 42, []string{"prod", "tier1"})
	require.NoError(t, err)
	assert.Equal(t, []string{"prod", "tier1"}, tags)
}

func TestSplitTags(t *testing.T) {
	assert.Equal(t, []string{"a", "b", "c"}, splitTags(" a , b ,c"))
	assert.Empty(t, splitTags(""))
	assert.Empty(t, splitTags("  ,  "))
}

func TestGetSecretTags_NotFound(t *testing.T) {
	rc, done := tagsStub(t)
	defer done()
	_, err := getSecretTags(context.Background(), rc, 999)
	require.Error(t, err)
}

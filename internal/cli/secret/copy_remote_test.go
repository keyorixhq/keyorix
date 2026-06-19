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

func copyStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets/5/copy" {
			b, _ := io.ReadAll(r.Body)
			var got map[string]interface{}
			_ = json.Unmarshal(b, &got)
			if got["environment_id"] != nil {
				_, _ = w.Write([]byte(`{"data":{"ID":42,"Name":"db"},"message":"Secret copied"}`))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close
}

func TestCopySecret(t *testing.T) {
	rc, done := copyStub(t)
	defer done()
	id, err := copySecret(context.Background(), rc, 5, 3, "db-prod")
	require.NoError(t, err)
	assert.Equal(t, uint(42), id)
}

func TestCopySecret_NotFound(t *testing.T) {
	rc, done := copyStub(t)
	defer done()
	_, err := copySecret(context.Background(), rc, 999, 3, "")
	require.Error(t, err)
}

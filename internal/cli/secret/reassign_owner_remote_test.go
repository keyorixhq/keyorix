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

func reassignStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/projects/5/secrets/reassign-owner" {
			// Echo back a count; assert the body carried the owner IDs.
			b, _ := io.ReadAll(r.Body)
			var got map[string]uint
			_ = json.Unmarshal(b, &got)
			if got["from_owner_id"] == 2 && got["to_owner_id"] == 3 {
				_, _ = w.Write([]byte(`{"data":{"reassigned":4}}`))
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

func TestReassignOwner(t *testing.T) {
	rc, done := reassignStub(t)
	defer done()
	n, err := reassignOwner(context.Background(), rc, 5, 2, 3)
	require.NoError(t, err)
	assert.Equal(t, 4, n)
}

func TestReassignOwner_NotFound(t *testing.T) {
	rc, done := reassignStub(t)
	defer done()
	_, err := reassignOwner(context.Background(), rc, 999, 2, 3)
	require.Error(t, err)
}

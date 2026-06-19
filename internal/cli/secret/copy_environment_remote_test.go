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

func copyEnvStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/projects/7/environments/3/copy-secrets" {
			b, _ := io.ReadAll(r.Body)
			var got map[string]interface{}
			_ = json.Unmarshal(b, &got)
			if got["target_environment_id"] != nil {
				_, _ = w.Write([]byte(`{"data":{"copied":4,"skipped":1},"message":""}`))
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

func TestCopyEnvironmentSecrets(t *testing.T) {
	rc, done := copyEnvStub(t)
	defer done()
	copied, skipped, err := copyEnvironmentSecrets(context.Background(), rc, 7, 3, 5)
	require.NoError(t, err)
	assert.Equal(t, 4, copied)
	assert.Equal(t, 1, skipped)
}

func TestCopyEnvironmentSecrets_NotFound(t *testing.T) {
	rc, done := copyEnvStub(t)
	defer done()
	_, _, err := copyEnvironmentSecrets(context.Background(), rc, 99, 3, 5)
	require.Error(t, err)
}

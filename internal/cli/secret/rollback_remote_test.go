package secret

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runRollbackRemote should POST {"version":N} to /secrets/{id}/rollback and
// surface server errors verbatim.
func TestRunRollbackRemote(t *testing.T) {
	var gotPath string
	var postBody map[string]interface{}
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &postBody)
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"ID":42,"Name":"db-pass"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	t.Run("posts version to the rollback route", func(t *testing.T) {
		status = http.StatusOK
		postBody = nil
		require.NoError(t, runRollbackRemote(rc, 42, 3))
		assert.Equal(t, "/api/v1/secrets/42/rollback", gotPath)
		assert.EqualValues(t, 3, postBody["version"])
	})

	t.Run("surfaces a server error (e.g. current/unknown version)", func(t *testing.T) {
		status = http.StatusBadRequest
		err := runRollbackRemote(rc, 42, 9)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "400")
	})
}

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

func TestRunSuspendResumeRemote(t *testing.T) {
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
		postBody = map[string]interface{}{}
		_ = json.Unmarshal(b, &postBody)
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"ID":42,"Name":"db"}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	t.Run("suspend posts to the suspend route with the reason", func(t *testing.T) {
		status = http.StatusOK
		require.NoError(t, runSuspendRemote(rc, 42, "suspected leak"))
		assert.Equal(t, "/api/v1/secrets/42/suspend", gotPath)
		assert.Equal(t, "suspected leak", postBody["reason"])
	})

	t.Run("suspend omits an empty reason", func(t *testing.T) {
		status = http.StatusOK
		require.NoError(t, runSuspendRemote(rc, 42, ""))
		_, has := postBody["reason"]
		assert.False(t, has, "no reason key when none given")
	})

	t.Run("resume posts to the resume route", func(t *testing.T) {
		status = http.StatusOK
		require.NoError(t, runResumeRemote(rc, 42))
		assert.Equal(t, "/api/v1/secrets/42/resume", gotPath)
	})

	t.Run("surfaces a server error", func(t *testing.T) {
		status = http.StatusForbidden
		err := runSuspendRemote(rc, 42, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "403")
	})
}

package anomalies

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAnomaliesUsesSharedRemoteClient guards #348: runList/runAcknowledge must
// go through common.RemoteClient (a single, shared HTTP client) rather than
// building their own ad hoc http.DefaultClient.Do(req) — the same duplicate
// no-timeout hang risk #315 already flags for the shared client.
func TestAnomaliesUsesSharedRemoteClient(t *testing.T) {
	var gotPath, gotMethod, gotAuth string
	status := http.StatusOK
	body := `{"data":{"alerts":[{"ID":7,"SecretName":"db","AlertType":"new_ip","Severity":"high","Description":"new ip seen","AccessedBy":"alice","IPAddress":"10.0.0.1","DetectedAt":"2026-07-01T00:00:00Z","Acknowledged":false}],"total":1}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		if r.URL.Path == "/api/v1/audit/anomalies" {
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"acknowledged":true}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	t.Run("list hits the anomalies route with the bearer token via the shared client", func(t *testing.T) {
		status = http.StatusOK
		require.NoError(t, runListRemote(rc))
		assert.Equal(t, "/api/v1/audit/anomalies", gotPath)
		assert.Equal(t, http.MethodGet, gotMethod)
		assert.Equal(t, "Bearer test-token", gotAuth)
	})

	t.Run("list surfaces a server error", func(t *testing.T) {
		status = http.StatusForbidden
		err := runListRemote(rc)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "403")
	})

	t.Run("acknowledge posts to the acknowledge route via the shared client", func(t *testing.T) {
		status = http.StatusOK
		require.NoError(t, runAcknowledgeRemote(rc, 7))
		assert.Equal(t, "/api/v1/audit/anomalies/7/acknowledge", gotPath)
		assert.Equal(t, http.MethodPost, gotMethod)
		assert.Equal(t, "Bearer test-token", gotAuth)
	})

	t.Run("acknowledge surfaces a server error", func(t *testing.T) {
		status = http.StatusNotFound
		err := runAcknowledgeRemote(rc, 7)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "404")
	})
}

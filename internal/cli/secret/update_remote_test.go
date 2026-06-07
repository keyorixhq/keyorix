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

// runUpdateRemote should GET current state then PUT only the changed fields,
// against the server rather than a local SQLite file.
func TestRunUpdateRemote(t *testing.T) {
	var putBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"data":{"ID":42,"Name":"db-pass","Type":"password"}}`))
		case http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &putBody)
			_, _ = w.Write([]byte(`{"data":{"ID":42,"Name":"db-pass","Type":"password"}}`))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	updateMaxReads = -1 // sentinel: "no change" (flag default isn't applied in tests)
	updateFromFile = ""

	t.Run("value + clear expiration", func(t *testing.T) {
		putBody = nil
		updateID, updateValue, updateClearExp, updateExpiration, updateInteractive = 42, "new-value", true, "", false
		require.NoError(t, runUpdateRemote(rc))
		assert.Equal(t, "new-value", putBody["value"])
		assert.Equal(t, true, putBody["clear_expiration"])
		_, hasExp := putBody["expiration"]
		assert.False(t, hasExp, "clear and set are mutually exclusive")
	})

	t.Run("set expiration", func(t *testing.T) {
		putBody = nil
		updateID, updateValue, updateClearExp, updateExpiration, updateInteractive = 42, "", false, "2030-01-02T03:04:05Z", false
		require.NoError(t, runUpdateRemote(rc))
		assert.Equal(t, "2030-01-02T03:04:05Z", putBody["expiration"])
		_, hasClear := putBody["clear_expiration"]
		assert.False(t, hasClear)
	})
}

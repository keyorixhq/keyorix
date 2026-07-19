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

// bulkRotateStub builds a test HTTP server that handles POST
// /api/v1/projects/7/secrets/bulk-rotate. When capture is non-nil it records the
// decoded request body there.
func bulkRotateStub(t *testing.T, status int, responseBody string, capture *map[string]interface{}) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/projects/7/secrets/bulk-rotate" {
			if capture != nil {
				b, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(b, capture)
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(responseBody))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close
}

func TestBulkRotate_Remote_Success(t *testing.T) {
	const body = `{"data":{"triggered":[1,2,3],"total":3}}`
	var got map[string]interface{}
	rc, done := bulkRotateStub(t, http.StatusOK, body, &got)
	defer done()

	result, err := postBulkRotate(context.Background(), rc, 7, []uint{1, 2, 3}, 0, "")
	require.NoError(t, err)

	assert.Equal(t, 3, len(result.Triggered))
	assert.Empty(t, result.Failed)
	assert.Equal(t, 3, result.Total)

	// Verify the request body contained the secret IDs.
	ids, ok := got["secret_ids"].([]interface{})
	require.True(t, ok, "secret_ids should be present in the request body")
	assert.Len(t, ids, 3)
}

func TestBulkRotate_Remote_PartialFailure(t *testing.T) {
	const body = `{"data":{"triggered":[1],"failed":[{"secret_id":2,"name":"broken","error":"no rotation config"}],"total":2}}`
	rc, done := bulkRotateStub(t, http.StatusOK, body, nil)
	defer done()

	result, err := postBulkRotate(context.Background(), rc, 7, []uint{1, 2}, 0, "")
	require.NoError(t, err)

	assert.Len(t, result.Triggered, 1)
	assert.Equal(t, uint(1), result.Triggered[0])
	require.Len(t, result.Failed, 1)
	assert.Equal(t, uint(2), result.Failed[0].SecretID)
	assert.Equal(t, "broken", result.Failed[0].Name)
	assert.Contains(t, result.Failed[0].Error, "no rotation config")
}

func TestBulkRotate_Remote_RequiresConfirm(t *testing.T) {
	// Reset global flag so it is not set from a previous test run.
	bulkRotateConfirm = false
	bulkRotateProject = 7

	err := bulkRotateCmd.RunE(bulkRotateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--confirm")

	// No HTTP call is made (the stub is not even created — we expect an early return).
}

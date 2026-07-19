// create_remote_folder_test.go — tests that runCreateRemote sends (or omits)
// parent_id in the HTTP request body based on the --folder flag.
package secret

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createStubResponse is the minimal valid JSON the stub server returns.
// decodeEnvelope in RemoteClient strips the {"data":…} wrapper, so the inner
// object must be a valid SecretNode (only ID and Name are required for
// printCreatedSecret to not panic).
const createStubResponse = `{"success":true,"data":{"id":1,"name":"test","type":"generic","project_id":1,"environment_id":1,"status":"active","created_by":"cli-user","created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z"},"message":"created"}`

// TestRunCreateRemote_FolderFlag_SendsParentID asserts that when ParentID is
// set on the request, runCreateRemote includes "parent_id" in the POST body.
func TestRunCreateRemote_FolderFlag_SendsParentID(t *testing.T) {
	var capturedBody map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/secrets", r.URL.Path)

		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &capturedBody))

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(createStubResponse))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok, "expected remote client to be created")

	parentID := uint(42)
	req := &core.CreateSecretRequest{
		Name:          "my-secret",
		Value:         []byte("secret-value"),
		Type:          "generic",
		ProjectID:     1,
		EnvironmentID: 1,
		ParentID:      &parentID,
	}

	err := runCreateRemote(context.Background(), rc, req)
	require.NoError(t, err)

	// JSON numbers unmarshal as float64 by default into interface{}.
	gotParentID, ok := capturedBody["parent_id"]
	require.True(t, ok, "expected parent_id key in request body")
	assert.Equal(t, float64(42), gotParentID, "parent_id should be 42")
}

// TestRunCreateRemote_NoFolderFlag_NoParentID asserts that when ParentID is
// nil, runCreateRemote does NOT include "parent_id" in the POST body.
func TestRunCreateRemote_NoFolderFlag_NoParentID(t *testing.T) {
	var capturedBody map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/secrets", r.URL.Path)

		raw, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &capturedBody))

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(createStubResponse))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok, "expected remote client to be created")

	req := &core.CreateSecretRequest{
		Name:          "my-secret",
		Value:         []byte("secret-value"),
		Type:          "generic",
		ProjectID:     1,
		EnvironmentID: 1,
		ParentID:      nil, // no folder
	}

	err := runCreateRemote(context.Background(), rc, req)
	require.NoError(t, err)

	_, present := capturedBody["parent_id"]
	assert.False(t, present, "parent_id should NOT be present in request body when ParentID is nil")
}

// move_remote_test.go — CLI-level tests for the secret move command.
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

// moveStub starts a minimal httptest server that accepts POST /api/v1/secrets/{id}/move.
func moveStub(t *testing.T) (*common.RemoteClient, func()) {
	t.Helper()
	var capturedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets/42/move" {
			b, _ := io.ReadAll(r.Body)
			capturedBody = b
			_, _ = w.Write([]byte(`{"success":true,"data":{"ID":42,"ParentID":7},"message":"Secret moved"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(func() { _ = capturedBody })
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close
}

// TestMoveSecret_SendsCorrectBody verifies that moveSecret POSTs {"parent_id": N}.
func TestMoveSecret_SendsCorrectBody(t *testing.T) {
	var captured map[string]uint
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets/42/move" {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &captured)
			_, _ = w.Write([]byte(`{"success":true,"data":{},"message":"Secret moved"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	err := moveSecret(context.Background(), rc, 42, 7)
	require.NoError(t, err)
	assert.Equal(t, uint(7), captured["parent_id"])
}

// TestMoveSecret_ToRoot_Body verifies that moveSecret sends parent_id=0 for root.
func TestMoveSecret_ToRoot_Body(t *testing.T) {
	var captured map[string]uint
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/secrets/10/move" {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &captured)
			_, _ = w.Write([]byte(`{"success":true,"data":{}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	err := moveSecret(context.Background(), rc, 10, 0)
	require.NoError(t, err)
	assert.Equal(t, uint(0), captured["parent_id"])
}

// TestMoveSecret_HappyPath verifies that moveSecret succeeds with a valid response.
func TestMoveSecret_HappyPath(t *testing.T) {
	rc, done := moveStub(t)
	defer done()
	err := moveSecret(context.Background(), rc, 42, 7)
	require.NoError(t, err)
}

// TestMoveSecret_ServerError verifies that moveSecret returns an error on non-200.
func TestMoveSecret_ServerError(t *testing.T) {
	rc, done := moveStub(t)
	defer done()
	// ID 999 is not served by the stub — returns 404.
	err := moveSecret(context.Background(), rc, 999, 7)
	require.Error(t, err)
}

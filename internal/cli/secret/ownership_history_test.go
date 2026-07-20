package secret

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newOwnershipHistoryClient(t *testing.T, handler http.HandlerFunc) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close
}

func setupOwnershipDisconnected(t *testing.T) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(dir, "nonexistent.yaml"))
}

func TestFetchOwnershipHistory_Success(t *testing.T) {
	rc, done := newOwnershipHistoryClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/secrets/42/ownership-history", r.URL.Path)
		_, _ = w.Write([]byte(`{"data":{"ownership_history":[
			{"event_id":1,"from_id":10,"to_id":20,"changed_by":5,"changed_at":"2026-01-01T00:00:00Z","description":"transferred to ops"},
			{"event_id":2,"from_id":20,"to_id":30,"changed_by":5,"changed_at":"2026-02-01T00:00:00Z","description":"transferred to security"}
		]}}`))
	})
	defer done()

	records, err := fetchOwnershipHistory(context.Background(), rc, 42)
	require.NoError(t, err)
	require.Len(t, records, 2)
	assert.Equal(t, uint(1), records[0].EventID)
	assert.Equal(t, uint(10), records[0].FromID)
	assert.Equal(t, uint(20), records[0].ToID)
	assert.Equal(t, uint(30), records[1].ToID)
}

func TestFetchOwnershipHistory_Empty(t *testing.T) {
	rc, done := newOwnershipHistoryClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"ownership_history":[]}}`))
	})
	defer done()

	records, err := fetchOwnershipHistory(context.Background(), rc, 5)
	require.NoError(t, err)
	assert.Empty(t, records)
}

func TestFetchOwnershipHistory_ServerError(t *testing.T) {
	rc, done := newOwnershipHistoryClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	defer done()

	_, err := fetchOwnershipHistory(context.Background(), rc, 5)
	require.Error(t, err)
}

func TestOwnershipHistoryCmd_MissingID(t *testing.T) {
	orig := ownershipHistoryID
	defer func() { ownershipHistoryID = orig }()
	ownershipHistoryID = 0

	err := ownershipHistoryCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id is required")
}

func TestOwnershipHistoryCmd_NotConnected(t *testing.T) {
	orig := ownershipHistoryID
	defer func() { ownershipHistoryID = orig }()
	ownershipHistoryID = 1

	setupOwnershipDisconnected(t)

	err := ownershipHistoryCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestOwnershipHistoryCmd_PrintsTable(t *testing.T) {
	orig := ownershipHistoryID
	defer func() { ownershipHistoryID = orig }()
	ownershipHistoryID = 42

	_, done := newOwnershipHistoryClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"ownership_history":[
			{"event_id":1,"from_id":10,"to_id":20,"changed_by":5,"changed_at":"2026-01-01T00:00:00Z","description":"test transfer"}
		]}}`))
	})
	defer done()

	out := captureStdout(t, func() {
		require.NoError(t, ownershipHistoryCmd.RunE(nil, nil))
	})
	assert.Contains(t, out, "EVENT ID")
	assert.Contains(t, out, "FROM")
}

func TestOwnershipHistoryCmd_EmptyPrintsMessage(t *testing.T) {
	orig := ownershipHistoryID
	defer func() { ownershipHistoryID = orig }()
	ownershipHistoryID = 99

	_, done := newOwnershipHistoryClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"ownership_history":[]}}`))
	})
	defer done()

	out := captureStdout(t, func() {
		require.NoError(t, ownershipHistoryCmd.RunE(nil, nil))
	})
	assert.Contains(t, out, "No ownership transfers")
}

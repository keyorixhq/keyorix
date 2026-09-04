// recycle_rune_test.go — exercises trashCmd.RunE and restoreCmd.RunE directly
// (recycle_remote_test.go only tests fetchTrash/restoreSecret).
package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func recycleRuneStub(t *testing.T, handler http.HandlerFunc) func() {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	return srv.Close
}

func resetTrashFlags(t *testing.T) {
	t.Helper()
	origProject, origLimit := trashProject, trashLimit
	t.Cleanup(func() { trashProject = origProject; trashLimit = origLimit })
}

func resetRestoreFlags(t *testing.T) {
	t.Helper()
	orig := restoreID
	t.Cleanup(func() { restoreID = orig })
}

func TestTrashCmd_MissingProject(t *testing.T) {
	resetTrashFlags(t)
	trashProject = 0
	err := trashCmd.RunE(trashCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project")
}

func TestTrashCmd_NoServer(t *testing.T) {
	resetTrashFlags(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	trashProject = 4
	err := trashCmd.RunE(trashCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestTrashCmd_Success_Empty(t *testing.T) {
	resetTrashFlags(t)
	done := recycleRuneStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"deleted":[]}}`))
	})
	defer done()
	trashProject = 4

	out := captureStdoutForFolder(t, func() {
		err := trashCmd.RunE(trashCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "Recycle bin is empty")
}

func TestTrashCmd_Success_WithLimitAndRows(t *testing.T) {
	resetTrashFlags(t)
	var gotQuery string
	done := recycleRuneStub(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"deleted":[{"id":1,"name":"gone","type":"generic","classification":"internal","deleted_at":"2026-01-01"}]}}`))
	})
	defer done()
	trashProject = 4
	trashLimit = 10

	out := captureStdoutForFolder(t, func() {
		err := trashCmd.RunE(trashCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, gotQuery, "limit=10")
	assert.Contains(t, out, "gone")
}

func TestTrashCmd_FetchError(t *testing.T) {
	resetTrashFlags(t)
	done := recycleRuneStub(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	defer done()
	trashProject = 4

	err := trashCmd.RunE(trashCmd, nil)
	require.Error(t, err)
}

func TestRestoreCmd_MissingID(t *testing.T) {
	resetRestoreFlags(t)
	restoreID = 0
	err := restoreCmd.RunE(restoreCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id")
}

func TestRestoreCmd_NoServer(t *testing.T) {
	resetRestoreFlags(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	restoreID = 5
	err := restoreCmd.RunE(restoreCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestRestoreCmd_Success(t *testing.T) {
	resetRestoreFlags(t)
	done := recycleRuneStub(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/secrets/5/restore", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":5,"restored":true}}`))
	})
	defer done()
	restoreID = 5

	out := captureStdoutForFolder(t, func() {
		err := restoreCmd.RunE(restoreCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "restored")
}

func TestRestoreCmd_APIError(t *testing.T) {
	resetRestoreFlags(t)
	done := recycleRuneStub(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	defer done()
	restoreID = 5

	err := restoreCmd.RunE(restoreCmd, nil)
	require.Error(t, err)
}

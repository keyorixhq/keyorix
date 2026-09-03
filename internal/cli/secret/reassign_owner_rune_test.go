// reassign_owner_rune_test.go — exercises reassignOwnerCmd.RunE directly
// (reassign_owner_remote_test.go only tests reassignOwner).
package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetReassignOwnerFlags(t *testing.T) {
	t.Helper()
	origProject, origFrom, origTo := reassignProject, reassignFrom, reassignTo
	t.Cleanup(func() {
		reassignProject = origProject
		reassignFrom = origFrom
		reassignTo = origTo
	})
}

func TestReassignOwnerCmd_MissingFlags(t *testing.T) {
	resetReassignOwnerFlags(t)
	reassignProject, reassignFrom, reassignTo = 0, 0, 0
	err := reassignOwnerCmd.RunE(reassignOwnerCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project")
}

func TestReassignOwnerCmd_NoServer(t *testing.T) {
	resetReassignOwnerFlags(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	reassignProject, reassignFrom, reassignTo = 1, 2, 3
	err := reassignOwnerCmd.RunE(reassignOwnerCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestReassignOwnerCmd_Success(t *testing.T) {
	resetReassignOwnerFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/projects/1/secrets/reassign-owner", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"reassigned":4}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	reassignProject, reassignFrom, reassignTo = 1, 2, 3

	out := captureStdoutForFolder(t, func() {
		err := reassignOwnerCmd.RunE(reassignOwnerCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "Reassigned 4 secret(s)")
}

func TestReassignOwnerCmd_APIError(t *testing.T) {
	resetReassignOwnerFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	reassignProject, reassignFrom, reassignTo = 1, 2, 3

	err := reassignOwnerCmd.RunE(reassignOwnerCmd, nil)
	require.Error(t, err)
}

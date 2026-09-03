// copy_environment_rune_test.go — exercises copyEnvironmentCmd.RunE directly
// (copy_environment_remote_test.go only tests copyEnvironmentSecrets).
package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetCopyEnvFlags(t *testing.T) {
	t.Helper()
	origProject, origFrom, origTo := copyEnvProject, copyEnvFrom, copyEnvTo
	t.Cleanup(func() {
		copyEnvProject = origProject
		copyEnvFrom = origFrom
		copyEnvTo = origTo
	})
}

func TestCopyEnvironmentCmd_MissingFlags(t *testing.T) {
	resetCopyEnvFlags(t)
	copyEnvProject, copyEnvFrom, copyEnvTo = 0, 0, 0
	err := copyEnvironmentCmd.RunE(copyEnvironmentCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project")
}

func TestCopyEnvironmentCmd_SameFromTo(t *testing.T) {
	resetCopyEnvFlags(t)
	copyEnvProject, copyEnvFrom, copyEnvTo = 1, 2, 2
	err := copyEnvironmentCmd.RunE(copyEnvironmentCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must differ")
}

func TestCopyEnvironmentCmd_NoServer(t *testing.T) {
	resetCopyEnvFlags(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	copyEnvProject, copyEnvFrom, copyEnvTo = 1, 2, 3
	err := copyEnvironmentCmd.RunE(copyEnvironmentCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestCopyEnvironmentCmd_Success(t *testing.T) {
	resetCopyEnvFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/projects/1/environments/2/copy-secrets", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"copied":3,"skipped":1}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	copyEnvProject, copyEnvFrom, copyEnvTo = 1, 2, 3

	out := captureStdoutForFolder(t, func() {
		err := copyEnvironmentCmd.RunE(copyEnvironmentCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "3 copied")
	assert.Contains(t, out, "1 skipped")
}

func TestCopyEnvironmentCmd_APIError(t *testing.T) {
	resetCopyEnvFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	copyEnvProject, copyEnvFrom, copyEnvTo = 1, 2, 3

	err := copyEnvironmentCmd.RunE(copyEnvironmentCmd, nil)
	require.Error(t, err)
}

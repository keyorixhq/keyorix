// copy_rune_test.go — exercises copyCmd.RunE directly (copy_remote_test.go only
// tests copySecret).
package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetCopyFlags(t *testing.T) {
	t.Helper()
	origID, origToEnv, origName := copyID, copyToEnv, copyNewName
	t.Cleanup(func() {
		copyID = origID
		copyToEnv = origToEnv
		copyNewName = origName
	})
}

func TestCopyCmd_MissingFlags(t *testing.T) {
	resetCopyFlags(t)
	copyID, copyToEnv = 0, 0
	err := copyCmd.RunE(copyCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id")
}

func TestCopyCmd_NoServer(t *testing.T) {
	resetCopyFlags(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	copyID, copyToEnv = 5, 3
	err := copyCmd.RunE(copyCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestCopyCmd_Success_DefaultName(t *testing.T) {
	resetCopyFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/secrets/5/copy", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"ID":99}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	copyID, copyToEnv = 5, 3
	copyNewName = ""

	out := captureStdoutForFolder(t, func() {
		err := copyCmd.RunE(copyCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "new secret 99")
}

func TestCopyCmd_Success_WithName(t *testing.T) {
	resetCopyFlags(t)
	var capturedBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"ID":100}}`))
		_ = capturedBody
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	copyID, copyToEnv = 5, 3
	copyNewName = "renamed-copy"

	err := copyCmd.RunE(copyCmd, nil)
	require.NoError(t, err)
}

func TestCopyCmd_APIError(t *testing.T) {
	resetCopyFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	copyID, copyToEnv = 5, 3

	err := copyCmd.RunE(copyCmd, nil)
	require.Error(t, err)
}

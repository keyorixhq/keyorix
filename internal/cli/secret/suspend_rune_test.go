// suspend_rune_test.go — exercises suspendCmd.RunE and resumeCmd.RunE directly
// (suspend_remote_test.go only calls runSuspendRemote/runResumeRemote directly).
package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSuspendCmd_MissingID(t *testing.T) {
	origID := suspendID
	t.Cleanup(func() { suspendID = origID })
	suspendID = 0
	err := suspendCmd.RunE(suspendCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id")
}

func TestSuspendCmd_NoServer(t *testing.T) {
	origID := suspendID
	t.Cleanup(func() { suspendID = origID })
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	suspendID = 42
	err := suspendCmd.RunE(suspendCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestSuspendCmd_Success(t *testing.T) {
	origID := suspendID
	t.Cleanup(func() { suspendID = origID })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	suspendID = 42

	out := captureStdoutForFolder(t, func() {
		err := suspendCmd.RunE(suspendCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "suspended")
}

func TestResumeCmd_MissingID(t *testing.T) {
	origID := resumeID
	t.Cleanup(func() { resumeID = origID })
	resumeID = 0
	err := resumeCmd.RunE(resumeCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id")
}

func TestResumeCmd_NoServer(t *testing.T) {
	origID := resumeID
	t.Cleanup(func() { resumeID = origID })
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	resumeID = 42
	err := resumeCmd.RunE(resumeCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestResumeCmd_Success(t *testing.T) {
	origID := resumeID
	t.Cleanup(func() { resumeID = origID })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	resumeID = 42

	out := captureStdoutForFolder(t, func() {
		err := resumeCmd.RunE(resumeCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "resumed")
}

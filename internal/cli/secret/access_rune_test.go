// access_rune_test.go — exercises accessCmd.RunE and accessLogCmd.RunE directly
// (access_remote_test.go only tests fetchAccessors/fetchAccessLog).
package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func accessRuneStub(t *testing.T, path, body string) func() {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	return srv.Close
}

func resetAccessFlags(t *testing.T) {
	t.Helper()
	orig := accessID
	t.Cleanup(func() { accessID = orig })
}

func resetAccessLogFlags(t *testing.T) {
	t.Helper()
	origID, origDays := accessLogID, accessLogDays
	t.Cleanup(func() { accessLogID = origID; accessLogDays = origDays })
}

func TestAccessCmd_MissingID(t *testing.T) {
	resetAccessFlags(t)
	accessID = 0
	err := accessCmd.RunE(accessCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id")
}

func TestAccessCmd_NoServer(t *testing.T) {
	resetAccessFlags(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	accessID = 7
	err := accessCmd.RunE(accessCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestAccessCmd_Success_Empty(t *testing.T) {
	resetAccessFlags(t)
	done := accessRuneStub(t, "/api/v1/secrets/7/access", `{"data":{"accessors":[]}}`)
	defer done()
	accessID = 7

	out := captureStdoutForFolder(t, func() {
		err := accessCmd.RunE(accessCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "No accessors")
}

func TestAccessCmd_Success_WithRows(t *testing.T) {
	resetAccessFlags(t)
	done := accessRuneStub(t, "/api/v1/secrets/7/access", `{"data":{"accessors":[{"username":"alice","permission":"read","source":"direct"}]}}`)
	defer done()
	accessID = 7

	out := captureStdoutForFolder(t, func() {
		err := accessCmd.RunE(accessCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "alice")
	assert.Contains(t, out, "direct")
}

func TestAccessCmd_FetchError(t *testing.T) {
	resetAccessFlags(t)
	done := accessRuneStub(t, "/nonexistent", `{}`)
	defer done()
	accessID = 7

	err := accessCmd.RunE(accessCmd, nil)
	require.Error(t, err)
}

func TestAccessLogCmd_MissingID(t *testing.T) {
	resetAccessLogFlags(t)
	accessLogID = 0
	err := accessLogCmd.RunE(accessLogCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id")
}

func TestAccessLogCmd_NoServer(t *testing.T) {
	resetAccessLogFlags(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	accessLogID = 7
	err := accessLogCmd.RunE(accessLogCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestAccessLogCmd_Success_Empty(t *testing.T) {
	resetAccessLogFlags(t)
	done := accessRuneStub(t, "/api/v1/secrets/7/access-log", `{"data":{"access_log":[]}}`)
	defer done()
	accessLogID = 7
	accessLogDays = 0

	out := captureStdoutForFolder(t, func() {
		err := accessLogCmd.RunE(accessLogCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "No reads")
}

func TestAccessLogCmd_Success_WithDaysAndRows(t *testing.T) {
	resetAccessLogFlags(t)
	done := accessRuneStub(t, "/api/v1/secrets/7/access-log", `{"data":{"access_log":[{"AccessedBy":"bob","Action":"read","IPAddress":"1.2.3.4","AccessTime":"2026-01-01T00:00:00Z"}]}}`)
	defer done()
	accessLogID = 7
	accessLogDays = 7

	out := captureStdoutForFolder(t, func() {
		err := accessLogCmd.RunE(accessLogCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "bob")
	assert.Contains(t, out, "1.2.3.4")
}

func TestAccessLogCmd_FetchError(t *testing.T) {
	resetAccessLogFlags(t)
	done := accessRuneStub(t, "/nonexistent", `{}`)
	defer done()
	accessLogID = 7

	err := accessLogCmd.RunE(accessLogCmd, nil)
	require.Error(t, err)
}

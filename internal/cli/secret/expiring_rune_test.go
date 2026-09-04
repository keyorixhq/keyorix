// expiring_rune_test.go — exercises expiringCmd.RunE directly
// (expiring_remote_test.go only tests fetchExpiring).
package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func expiringRuneStub(t *testing.T, path, body string) func() {
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

func resetExpiringFlags(t *testing.T) {
	t.Helper()
	origProject, origDays := expiringProject, expiringDays
	t.Cleanup(func() { expiringProject = origProject; expiringDays = origDays })
}

func TestExpiringCmd_MissingProject(t *testing.T) {
	resetExpiringFlags(t)
	expiringProject = 0
	err := expiringCmd.RunE(expiringCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--project")
}

func TestExpiringCmd_NoServer(t *testing.T) {
	resetExpiringFlags(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	expiringProject = 4
	err := expiringCmd.RunE(expiringCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestExpiringCmd_Success_Empty(t *testing.T) {
	resetExpiringFlags(t)
	done := expiringRuneStub(t, "/api/v1/projects/4/secrets/expiring", `{"data":{"expiring":[]}}`)
	defer done()
	expiringProject = 4

	out := captureStdoutForFolder(t, func() {
		err := expiringCmd.RunE(expiringCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "No expiring secrets")
}

func TestExpiringCmd_Success_ExpiredAndExpiring(t *testing.T) {
	resetExpiringFlags(t)
	done := expiringRuneStub(t, "/api/v1/projects/4/secrets/expiring",
		`{"data":{"expiring":[{"id":1,"name":"a","type":"generic","environment_id":1,"expiration":"2020-01-01","expired":true},{"id":2,"name":"b","type":"generic","environment_id":1,"expiration":"2030-01-01","expired":false}]}}`)
	defer done()
	expiringProject = 4
	expiringDays = 30

	out := captureStdoutForFolder(t, func() {
		err := expiringCmd.RunE(expiringCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "EXPIRED")
	assert.Contains(t, out, "expiring")
}

func TestExpiringCmd_FetchError(t *testing.T) {
	resetExpiringFlags(t)
	done := expiringRuneStub(t, "/nonexistent", `{}`)
	defer done()
	expiringProject = 4

	err := expiringCmd.RunE(expiringCmd, nil)
	require.Error(t, err)
}

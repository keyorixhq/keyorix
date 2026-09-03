// autorotate_rune_test.go — exercises autoRotateCmd.RunE (entirely untested
// before this file: no other test in the package references autoRotateCmd).
package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetAutoRotateFlags(t *testing.T) {
	t.Helper()
	origID, origOff, origLen, origCharset, origBackend, origRef :=
		autoRotateID, autoRotateOff, autoRotateLength, autoRotateCharset, autoRotateBackend, autoRotateRef
	t.Cleanup(func() {
		autoRotateID = origID
		autoRotateOff = origOff
		autoRotateLength = origLen
		autoRotateCharset = origCharset
		autoRotateBackend = origBackend
		autoRotateRef = origRef
	})
}

func TestAutoRotateCmd_NoServer(t *testing.T) {
	resetAutoRotateFlags(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	autoRotateID = 7
	err := autoRotateCmd.RunE(autoRotateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func autoRotateStub(t *testing.T, path string) func() {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path {
			require.Equal(t, http.MethodPatch, r.Method)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	return srv.Close
}

func TestAutoRotateCmd_Success_Enable(t *testing.T) {
	resetAutoRotateFlags(t)
	done := autoRotateStub(t, "/api/v1/secrets/7/auto-rotate")
	defer done()
	autoRotateID = 7
	autoRotateOff = false

	out := captureStdoutForFolder(t, func() {
		err := autoRotateCmd.RunE(autoRotateCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "enabled")
}

func TestAutoRotateCmd_Success_Disable(t *testing.T) {
	resetAutoRotateFlags(t)
	done := autoRotateStub(t, "/api/v1/secrets/7/auto-rotate")
	defer done()
	autoRotateID = 7
	autoRotateOff = true

	out := captureStdoutForFolder(t, func() {
		err := autoRotateCmd.RunE(autoRotateCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "disabled")
}

func TestAutoRotateCmd_Success_WithBackendAndRef(t *testing.T) {
	resetAutoRotateFlags(t)
	done := autoRotateStub(t, "/api/v1/secrets/7/auto-rotate")
	defer done()
	autoRotateID = 7
	autoRotateBackend = "vault"
	autoRotateRef = "secret/foo"
	autoRotateCharset = "hex"

	err := autoRotateCmd.RunE(autoRotateCmd, nil)
	require.NoError(t, err)
}

func TestAutoRotateCmd_APIError(t *testing.T) {
	resetAutoRotateFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	autoRotateID = 7

	err := autoRotateCmd.RunE(autoRotateCmd, nil)
	require.Error(t, err)
}

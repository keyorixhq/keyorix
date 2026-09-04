// classify_rune_test.go — exercises classifyCmd.RunE (entirely untested before
// this file: no other test in the package references classifyCmd).
package secret

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func resetClassifyFlags(t *testing.T) {
	t.Helper()
	origID, origLevel := classifyID, classifyLevel
	t.Cleanup(func() { classifyID = origID; classifyLevel = origLevel })
}

func TestClassifyCmd_MissingID(t *testing.T) {
	resetClassifyFlags(t)
	classifyID = 0
	err := classifyCmd.RunE(classifyCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--id")
}

func TestClassifyCmd_InvalidLevel(t *testing.T) {
	resetClassifyFlags(t)
	classifyID = 7
	classifyLevel = "bogus"
	err := classifyCmd.RunE(classifyCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--level")
}

func TestClassifyCmd_NoServer(t *testing.T) {
	resetClassifyFlags(t)
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	classifyID = 7
	classifyLevel = "confidential"
	err := classifyCmd.RunE(classifyCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestClassifyCmd_Success_WithLevel(t *testing.T) {
	resetClassifyFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPatch, r.Method)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	classifyID = 7
	classifyLevel = "confidential"

	out := captureStdoutForFolder(t, func() {
		err := classifyCmd.RunE(classifyCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "confidential")
}

func TestClassifyCmd_Success_ClearsToUnclassified(t *testing.T) {
	resetClassifyFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	classifyID = 7
	classifyLevel = ""

	out := captureStdoutForFolder(t, func() {
		err := classifyCmd.RunE(classifyCmd, nil)
		require.NoError(t, err)
	})
	assert.Contains(t, out, "unclassified")
}

func TestClassifyCmd_APIError(t *testing.T) {
	resetClassifyFlags(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
	classifyID = 7

	err := classifyCmd.RunE(classifyCmd, nil)
	require.Error(t, err)
}

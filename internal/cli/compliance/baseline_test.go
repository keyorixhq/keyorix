package compliance

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBaselineCmd_CSVToStdout(t *testing.T) {
	t.Cleanup(func() { baselineFormat = "csv"; baselineOutput = "" })
	baselineFormat = "csv"
	baselineOutput = ""

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/compliance/permission-baseline.csv", r.URL.Path)
		_, _ = w.Write([]byte("user_id,username,role,permission,scope\n1,alice,Admin,secrets.read,global\n"))
	})

	out := captureStdout(t, func() {
		require.NoError(t, baselineCmd.RunE(nil, nil))
	})
	assert.Contains(t, out, "user_id,username,role,permission,scope")
	assert.Contains(t, out, "alice")
}

func TestBaselineCmd_CSVToFile(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "baseline.csv")

	t.Cleanup(func() { baselineFormat = "csv"; baselineOutput = "" })
	baselineFormat = "csv"
	baselineOutput = outFile

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/compliance/permission-baseline.csv", r.URL.Path)
		_, _ = w.Write([]byte("user_id,username,role,permission,scope\n2,bob,Viewer,secrets.read,project:1\n"))
	})

	out := captureStdout(t, func() {
		require.NoError(t, baselineCmd.RunE(nil, nil))
	})
	assert.Contains(t, out, "baseline.csv")

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "bob")
}

func TestBaselineCmd_JSONToStdout(t *testing.T) {
	t.Cleanup(func() { baselineFormat = "csv"; baselineOutput = "" })
	baselineFormat = "json"
	baselineOutput = ""

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/compliance/permission-baseline", r.URL.Path)
		_, _ = w.Write([]byte(`{"data":{"rows":[{"user_id":1,"username":"alice","permission":"secrets.read","scope":"global"}]}}`))
	})

	out := captureStdout(t, func() {
		require.NoError(t, baselineCmd.RunE(nil, nil))
	})
	assert.Contains(t, out, "alice")
	assert.Contains(t, out, "secrets.read")
}

func TestBaselineCmd_JSONToFile(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "baseline.json")

	t.Cleanup(func() { baselineFormat = "csv"; baselineOutput = "" })
	baselineFormat = "json"
	baselineOutput = outFile

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"rows":[{"user_id":2,"username":"bob"}]}}`))
	})

	out := captureStdout(t, func() {
		require.NoError(t, baselineCmd.RunE(nil, nil))
	})
	assert.Contains(t, out, "baseline.json")

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	assert.Contains(t, string(data), "bob")
}

func TestBaselineCmd_UnknownFormat(t *testing.T) {
	t.Cleanup(func() { baselineFormat = "csv"; baselineOutput = "" })
	baselineFormat = "xml"
	baselineOutput = ""

	setupRemote(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	err := baselineCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "xml")
}

func TestBaselineCmd_NotConnected(t *testing.T) {
	setupDisconnected(t)
	t.Cleanup(func() { baselineFormat = "csv"; baselineOutput = "" })
	baselineFormat = "csv"
	baselineOutput = ""

	err := baselineCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

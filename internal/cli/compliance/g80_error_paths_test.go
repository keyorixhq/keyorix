package compliance

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// This file rounds out the compliance package's remaining uncovered error
// branches: the server-error path through common.RemoteClient.Get/Post/GetRaw
// for each command, and the os.WriteFile failure path for the JSON-format
// permission-baseline export. Follows the existing convention of returning
// http.StatusInternalServerError from the mock server (see
// rotation_backend_test.go, permission_changes_test.go).
// ---------------------------------------------------------------------------

func TestReport_ServerError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"success":false,"error":"boom"}`))
	})
	err := reportCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestExport_ServerError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"success":false,"error":"boom"}`))
	})
	exportOutput = ""
	err := exportCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// TestExport_WriteError covers the os.WriteFile error branch in exportCmd
// when --output points at a non-writable directory.
func TestExport_WriteError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"posture":{"ok":true}}}`))
	})
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	exportOutput = filepath.Join(dir, "pack.json")
	t.Cleanup(func() { exportOutput = "" })

	err := exportCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write")
}

func TestControls_ServerError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"success":false,"error":"boom"}`))
	})
	controlsCSV = false
	controlsOutput = ""
	t.Cleanup(func() { controlsCSV, controlsOutput = false, "" })

	err := controlsCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// TestInventory_ServerError covers the rc.GetRaw error branch inside emitCSV,
// shared by inventoryCmd, baselineCmd (csv format) and controlsCmd (--csv).
func TestInventory_ServerError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"success":false,"error":"forbidden"}`))
	})
	inventoryProject = 0
	inventoryOutput = ""
	t.Cleanup(func() { inventoryProject, inventoryOutput = 0, "" })

	err := inventoryCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestVerify_ServerError(t *testing.T) {
	dir := t.TempDir()
	packPath := filepath.Join(dir, "pack.json")
	require.NoError(t, os.WriteFile(packPath, []byte(`{"pack":true}`), 0o600))
	require.NoError(t, os.WriteFile(packPath+".sig", []byte("deadbeef"), 0o600))

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"success":false,"error":"boom"}`))
	})
	verifyFile = packPath
	verifySig = ""
	t.Cleanup(func() { verifyFile, verifySig = "", "" })

	err := verifyCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestDigest_ServerError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"success":false,"error":"boom"}`))
	})
	digestSend = false
	t.Cleanup(func() { digestSend = false })

	err := digestCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestDigest_Send_ServerError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"success":false,"error":"boom"}`))
	})
	digestSend = true
	t.Cleanup(func() { digestSend = false })

	err := digestCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// TestBaselineCmd_JSON_ServerError covers the c.Get error branch of the
// json-format path in baselineCmd.
func TestBaselineCmd_JSON_ServerError(t *testing.T) {
	t.Cleanup(func() { baselineFormat = "csv"; baselineOutput = "" })
	baselineFormat = "json"
	baselineOutput = ""

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"success":false,"error":"boom"}`))
	})

	err := baselineCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// TestBaselineCmd_JSONWriteError covers the os.WriteFile error branch of the
// json-format path in baselineCmd, when --output points at a non-writable
// directory.
func TestBaselineCmd_JSONWriteError(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	t.Cleanup(func() { baselineFormat = "csv"; baselineOutput = "" })
	baselineFormat = "json"
	baselineOutput = filepath.Join(dir, "baseline.json")

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"rows":[]}}`))
	})

	err := baselineCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write")
}

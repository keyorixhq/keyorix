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
// reportCmd — uncovered branches
// ---------------------------------------------------------------------------

// TestReport_NotDegraded_NoRetention exercises the non-degraded path, the
// "no note" branch (AuditIntegrity.Reason == ""), the legal-hold-inactive
// branch, and the retention-disabled branch.
func TestReport_NotDegraded_NoRetention(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{
			"generated_at":"2026-07-17T00:00:00Z",
			"audit_integrity":{"chain_verified":false,"chained_events":0,"checkpointed":false,"reason":""},
			"access_governance":{},"rotation":{},"identity":{},
			"emergency_access":{},"classification":{},"anomalies":{},
			"legal_hold":{"active":false,"reason":""},
			"retention":{"enabled":false},
			"degraded":false,"degraded_reasons":null
		}}`))
	})

	out := captureStdout(t, func() { require.NoError(t, reportCmd.RunE(nil, nil)) })

	assert.NotContains(t, out, "DEGRADED")
	// AuditIntegrity.Reason == "" → the "note" line must not appear
	assert.NotContains(t, out, "note           :")
	// legal_hold not active
	assert.Contains(t, out, "none — purges run normally")
	// retention disabled
	assert.Contains(t, out, "not configured — compliance records kept indefinitely")
}

// TestReport_RetDaysKeep checks that a 0-day retention window shows "keep".
func TestReport_RetDaysKeep(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{
			"generated_at":"2026-07-17T00:00:00Z",
			"audit_integrity":{},"access_governance":{},"rotation":{},
			"identity":{},"emergency_access":{},"classification":{},
			"anomalies":{},"legal_hold":{"active":false},
			"retention":{"enabled":true,"anomaly_alerts_days":0,"closed_access_reviews_days":0,"break_glass_days":0,"resolved_access_requests_days":0},
			"degraded":false
		}}`))
	})

	out := captureStdout(t, func() { require.NoError(t, reportCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "anomaly alerts          : keep")
	assert.Contains(t, out, "closed access reviews   : keep")
	assert.Contains(t, out, "break-glass register    : keep")
	assert.Contains(t, out, "resolved access requests: keep")
}

// ---------------------------------------------------------------------------
// exportCmd — not-connected path
// ---------------------------------------------------------------------------

func TestExport_NotConnected(t *testing.T) {
	setupDisconnected(t)
	err := exportCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// ---------------------------------------------------------------------------
// controlsCmd — uncovered branches
// ---------------------------------------------------------------------------

func TestControls_NotConnected(t *testing.T) {
	setupDisconnected(t)
	controlsCSV = false
	controlsOutput = ""
	t.Cleanup(func() { controlsCSV, controlsOutput = false, "" })

	err := controlsCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// TestControls_NoUnknown exercises the branch that skips the UNK warning when
// Summary.Unknown == 0.
func TestControls_NoUnknown(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{
			"generated_at":"2026-07-17",
			"summary":{"total":1,"pass":1,"gap":0,"not_configured":0,"unknown":0},
			"controls":[
				{"name":"Audit chain","area":"integrity","status":"pass","detail":"ok",
				 "frameworks":{"iso_27001":["A.12.4"],"soc2":[],"nis2":[],"dora":[]}}
			]
		}}`))
	})
	controlsCSV = false
	controlsOutput = ""
	t.Cleanup(func() { controlsCSV, controlsOutput = false, "" })

	out := captureStdout(t, func() { require.NoError(t, controlsCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "1 controls: 1 pass, 0 gap, 0 not-configured, 0 unknown")
	assert.NotContains(t, out, "could not be collected this run")
}

// TestControlsCSV_ToStdout exercises controlsCSV=true with no output file
// (emits bytes directly to stdout).
func TestControlsCSV_ToStdout(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/compliance/controls.csv", r.URL.Path)
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte("name,status\nAudit chain,pass\n"))
	})
	controlsCSV = true
	controlsOutput = ""
	t.Cleanup(func() { controlsCSV, controlsOutput = false, "" })

	out := captureStdout(t, func() { require.NoError(t, controlsCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "Audit chain,pass")
}

// TestControlsCSV_NotConnected covers the not-connected path when --csv is set.
func TestControlsCSV_NotConnected(t *testing.T) {
	setupDisconnected(t)
	controlsCSV = true
	controlsOutput = ""
	t.Cleanup(func() { controlsCSV, controlsOutput = false, "" })

	err := controlsCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// ---------------------------------------------------------------------------
// verifyCmd — uncovered branches
// ---------------------------------------------------------------------------

func TestVerify_NotConnected(t *testing.T) {
	dir := t.TempDir()
	packPath := filepath.Join(dir, "pack.json")
	require.NoError(t, os.WriteFile(packPath, []byte(`{}`), 0o600))
	require.NoError(t, os.WriteFile(packPath+".sig", []byte("deadbeef"), 0o600))

	setupDisconnected(t)
	verifyFile = packPath
	verifySig = ""
	t.Cleanup(func() { verifyFile, verifySig = "", "" })

	err := verifyCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// TestVerify_ExplicitSigFlag checks that --sig is used when provided instead of
// the default <file>.sig path.
func TestVerify_ExplicitSigFlag(t *testing.T) {
	dir := t.TempDir()
	packPath := filepath.Join(dir, "pack.json")
	sigPath := filepath.Join(dir, "custom.sig")
	require.NoError(t, os.WriteFile(packPath, []byte(`{"ok":true}`), 0o600))
	require.NoError(t, os.WriteFile(sigPath, []byte("  mysig  "), 0o600))

	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/compliance/evidence/verify", r.URL.Path)
		_, _ = w.Write([]byte(`{"success":true,"data":{"valid":true,"key_version":"v2"}}`))
	})
	verifyFile = packPath
	verifySig = sigPath
	t.Cleanup(func() { verifyFile, verifySig = "", "" })

	out := captureStdout(t, func() { require.NoError(t, verifyCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "VALID")
	assert.Contains(t, out, "key version v2")
}

// TestVerify_MissingPackFile covers the os.ReadFile error for the pack.
func TestVerify_MissingPackFile(t *testing.T) {
	dir := t.TempDir()
	verifyFile = filepath.Join(dir, "nonexistent.json")
	verifySig = ""
	t.Cleanup(func() { verifyFile, verifySig = "", "" })

	err := verifyCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read")
}

// TestVerify_MissingSigFile covers the os.ReadFile error for the signature.
func TestVerify_MissingSigFile(t *testing.T) {
	dir := t.TempDir()
	packPath := filepath.Join(dir, "pack.json")
	require.NoError(t, os.WriteFile(packPath, []byte(`{}`), 0o600))
	// deliberately do NOT create the .sig file
	verifyFile = packPath
	verifySig = ""
	t.Cleanup(func() { verifyFile, verifySig = "", "" })

	err := verifyCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read signature")
}

// ---------------------------------------------------------------------------
// inventoryCmd — uncovered branches
// ---------------------------------------------------------------------------

func TestInventory_NotConnected(t *testing.T) {
	setupDisconnected(t)
	inventoryProject = 0
	inventoryOutput = ""
	t.Cleanup(func() { inventoryProject, inventoryOutput = 0, "" })

	err := inventoryCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// TestInventory_ProjectScoped confirms --project builds the project-scoped path.
func TestInventory_ProjectScoped(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/projects/7/secrets/inventory.csv", r.URL.Path)
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte("name,project\napi-key,app\n"))
	})
	inventoryProject = 7
	inventoryOutput = ""
	t.Cleanup(func() { inventoryProject, inventoryOutput = 0, "" })

	out := captureStdout(t, func() { require.NoError(t, inventoryCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "api-key,app")
}

// TestInventory_ToFile covers the --output branch of inventoryCmd (via emitCSV).
func TestInventory_ToFile(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/secrets/inventory.csv", r.URL.Path)
		_, _ = w.Write([]byte("name,project\nsecret,proj\n"))
	})
	dir := t.TempDir()
	outPath := filepath.Join(dir, "inv.csv")
	inventoryProject = 0
	inventoryOutput = outPath
	t.Cleanup(func() { inventoryProject, inventoryOutput = 0, "" })

	out := captureStdout(t, func() { require.NoError(t, inventoryCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "Secret inventory CSV written to "+outPath)

	got, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Contains(t, string(got), "secret,proj")
}

// TestEmitCSV_WriteError covers the os.WriteFile error branch in emitCSV when
// the output path is not writable.
func TestEmitCSV_WriteError(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("col\nval\n"))
	})
	dir := t.TempDir()
	// Make the directory read-only so WriteFile fails.
	require.NoError(t, os.Chmod(dir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	inventoryProject = 0
	inventoryOutput = filepath.Join(dir, "out.csv")
	t.Cleanup(func() { inventoryProject, inventoryOutput = 0, "" })

	err := inventoryCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to write")
}

package compliance

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

// setupRemote points the compliance commands at a mock server via
// KEYORIX_SERVER/KEYORIX_TOKEN, so common.NewRemoteClient returns true.
func setupRemote(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")
}

// setupDisconnected forces common.NewRemoteClient to return false (no env server,
// no client cli.yaml, no remote main config).
func setupDisconnected(t *testing.T) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(dir, "nonexistent.yaml"))
}

func TestRetDays(t *testing.T) {
	assert.Equal(t, "keep", retDays(0))
	assert.Equal(t, "keep", retDays(-5))
	assert.Equal(t, "30d", retDays(30))
}

func TestYesNo(t *testing.T) {
	assert.Equal(t, "yes", yesNo(true))
	assert.Equal(t, "no", yesNo(false))
}

func TestStatusMark(t *testing.T) {
	assert.Equal(t, "PASS", statusMark("pass"))
	assert.Equal(t, "GAP ", statusMark("gap"))
	assert.Equal(t, "UNK ", statusMark("unknown"))
	assert.Equal(t, "n/a ", statusMark("not_configured"))
	assert.Equal(t, "n/a ", statusMark("anything-else"))
}

func TestJoinRefs(t *testing.T) {
	assert.Equal(t, "—", joinRefs())
	assert.Equal(t, "—", joinRefs([]string{}, nil))
	assert.Equal(t, "A.12.4", joinRefs([]string{"A.12.4"}))
	assert.Equal(t, "A.12.4, CC7.2", joinRefs([]string{"A.12.4"}, []string{"CC7.2"}))
	assert.Equal(t, "a, b, c", joinRefs([]string{"a", "b"}, []string{"c"}))
}

const posturePayload = `{"success":true,"data":{
	"generated_at":"2026-07-10T00:00:00Z",
	"audit_integrity":{"chain_verified":true,"chained_events":42,"checkpointed":true,"reason":"anchored"},
	"access_governance":{"projects":5,"projects_with_open_campaign":1,"projects_never_reviewed":2,"open_campaigns":1,"pending_items":3,"projects_overdue":1,"dormant_role_grants":0,"sod_violations":0},
	"rotation":{"covered_secrets":10,"overdue":2,"due_soon":1},
	"identity":{"active_users":8,"users_with_second_factor":6,"second_factor_percent":75},
	"emergency_access":{"active_activations":0,"total_activations":3},
	"classification":{"total_secrets":20,"public":1,"internal":5,"confidential":10,"restricted":4,"unclassified":0,"dynamic_configs":{"total":2,"restricted":1},"machine_identities":{"total":3},"machine_credentials":{"total":1}},
	"anomalies":{"unacknowledged":1,"high_severity_open":0},
	"legal_hold":{"active":true,"reason":"litigation-2026"},
	"retention":{"enabled":true,"anomaly_alerts_days":30,"closed_access_reviews_days":0,"break_glass_days":365,"resolved_access_requests_days":90},
	"degraded":true,
	"degraded_reasons":["anomaly subsystem timeout"]
}}`

func TestReport_Remote(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/compliance/posture", r.URL.Path)
		_, _ = w.Write([]byte(posturePayload))
	})

	out := captureStdout(t, func() { require.NoError(t, reportCmd.RunE(nil, nil)) })

	assert.Contains(t, out, "DEGRADED SNAPSHOT")
	assert.Contains(t, out, "anomaly subsystem timeout")
	assert.Contains(t, out, "chain verified : yes (42 chained events)")
	assert.Contains(t, out, "note           : anchored")
	assert.Contains(t, out, "ACTIVE — purges blocked (litigation-2026)")
	assert.Contains(t, out, "anomaly alerts          : 30d")
	assert.Contains(t, out, "closed access reviews   : keep") // 0 days -> keep
	assert.Contains(t, out, "with second factor  : 6 (75%)")
}

func TestReport_NotConnected(t *testing.T) {
	setupDisconnected(t)
	err := reportCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestControls_Remote(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/compliance/controls", r.URL.Path)
		_, _ = w.Write([]byte(`{"success":true,"data":{"generated_at":"2026-07-10","summary":{"total":3,"pass":1,"gap":1,"not_configured":0,"unknown":1},"controls":[
			{"name":"Audit chain","area":"integrity","status":"pass","detail":"chain verified","frameworks":{"iso_27001":["A.12.4"],"soc2":["CC7.2"],"nis2":[],"dora":[]}},
			{"name":"MFA","area":"identity","status":"gap","detail":"coverage low","frameworks":{"iso_27001":["A.9.4"]}},
			{"name":"Anomalies","area":"detect","status":"unknown","detail":"collection failed","frameworks":{}}
		]}}`))
	})

	controlsCSV = false
	controlsOutput = ""
	t.Cleanup(func() { controlsCSV, controlsOutput = false, "" })

	out := captureStdout(t, func() { require.NoError(t, controlsCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "3 controls: 1 pass, 1 gap, 0 not-configured, 1 unknown")
	assert.Contains(t, out, "could not be collected this run")
	assert.Contains(t, out, "[PASS] Audit chain (integrity)")
	assert.Contains(t, out, "[GAP ] MFA (identity)")
	assert.Contains(t, out, "[UNK ] Anomalies (detect)")
	assert.Contains(t, out, "ISO: A.12.4 | SOC2: CC7.2 | NIS2: — | DORA: —")
}

func TestControls_OutputWithoutCSVRejected(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {})
	controlsCSV = false
	controlsOutput = "/tmp/x.csv"
	t.Cleanup(func() { controlsCSV, controlsOutput = false, "" })

	err := controlsCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--output is only valid together with --csv")
}

func TestControlsCSV_And_EmitCSV(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/compliance/controls.csv", r.URL.Path)
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte("name,status\nAudit chain,pass\n"))
	})
	dir := t.TempDir()
	outPath := filepath.Join(dir, "controls.csv")
	controlsCSV = true
	controlsOutput = outPath
	t.Cleanup(func() { controlsCSV, controlsOutput = false, "" })

	out := captureStdout(t, func() { require.NoError(t, controlsCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "written to "+outPath)

	got, err := os.ReadFile(outPath)
	require.NoError(t, err)
	assert.Contains(t, string(got), "Audit chain,pass")
}

func TestExport_ToStdoutAndFile(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/compliance/evidence", r.URL.Path)
		_, _ = w.Write([]byte(`{"success":true,"data":{"posture":{"ok":true},"anchor":"abc"}}`))
	})

	// stdout
	exportOutput = ""
	out := captureStdout(t, func() { require.NoError(t, exportCmd.RunE(nil, nil)) })
	assert.Contains(t, out, `"anchor": "abc"`) // pretty-indented

	// file
	dir := t.TempDir()
	exportOutput = filepath.Join(dir, "pack.json")
	t.Cleanup(func() { exportOutput = "" })
	out = captureStdout(t, func() { require.NoError(t, exportCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "Evidence pack written to")
	got, err := os.ReadFile(exportOutput)
	require.NoError(t, err)
	assert.Contains(t, string(got), "anchor")
}

func TestInventory_EmitsCSV(t *testing.T) {
	setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/secrets/inventory.csv", r.URL.Path)
		_, _ = w.Write([]byte("name,project\ndb-pw,web\n"))
	})
	inventoryProject = 0
	inventoryOutput = ""
	t.Cleanup(func() { inventoryProject, inventoryOutput = 0, "" })

	out := captureStdout(t, func() { require.NoError(t, inventoryCmd.RunE(nil, nil)) })
	assert.Contains(t, out, "db-pw,web")
}

func TestVerify_RequiresFile(t *testing.T) {
	verifyFile = ""
	err := verifyCmd.RunE(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--file is required")
}

func TestVerify_ValidAndInvalid(t *testing.T) {
	dir := t.TempDir()
	packPath := filepath.Join(dir, "pack.json")
	require.NoError(t, os.WriteFile(packPath, []byte(`{"pack":true}`), 0o600))
	require.NoError(t, os.WriteFile(packPath+".sig", []byte("deadbeef"), 0o600))

	t.Run("valid", func(t *testing.T) {
		setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/api/v1/compliance/evidence/verify", r.URL.Path)
			_, _ = w.Write([]byte(`{"success":true,"data":{"valid":true,"key_version":"v1"}}`))
		})
		verifyFile = packPath
		verifySig = ""
		t.Cleanup(func() { verifyFile, verifySig = "", "" })
		out := captureStdout(t, func() { require.NoError(t, verifyCmd.RunE(nil, nil)) })
		assert.Contains(t, out, "VALID")
		assert.Contains(t, out, "key version v1")
	})

	t.Run("invalid", func(t *testing.T) {
		setupRemote(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"success":true,"data":{"valid":false,"reason":"tampered"}}`))
		})
		verifyFile = packPath
		verifySig = ""
		t.Cleanup(func() { verifyFile, verifySig = "", "" })
		var out string
		var err error
		out = captureStdout(t, func() { err = verifyCmd.RunE(nil, nil) })
		require.Error(t, err)
		assert.Contains(t, out, "NOT VERIFIED — tampered")
	})
}

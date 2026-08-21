// audit_coverage_test.go — additional coverage for branches the existing
// suite doesn't reach:
//
//   - the client()-returns-error path as actually taken by each command's
//     RunE/run* function (verify, export, checkpoint, migrate-chain-encoding,
//     logs, search) — the existing "NoClient" tests in audit_s18_test.go and
//     audit_search_test.go only clear KEYORIX_SERVER/KEYORIX_TOKEN, which on a
//     machine with a leftover ~/.keyorix/cli.yaml (written by a previous
//     `keyorix connect`) still resolves to a remote via the config-file
//     fallback in common.ResolveRemote — so those tests spuriously dial that
//     stale server instead of exercising the "not connected" branch. This file
//     additionally redirects HOME (and clears XDG_CONFIG_HOME) to an empty
//     temp directory so ResolveRemote's config-file fallback has nothing to
//     find, making the "not connected" branch deterministically reachable
//     regardless of the local machine's state.
//   - exportCmd's CSV path when a page event fails to unmarshal into
//     csvEventRow (the json.Unmarshal error → continue branch).
package audit

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isolateFromLocalConfig clears every source common.ResolveRemote consults
// (env vars, ~/.keyorix/cli.yaml via a redirected empty HOME) so client()
// deterministically returns the "not connected" error, independent of
// whatever remote config a previous `keyorix connect` may have left on this
// machine.
func isolateFromLocalConfig(t *testing.T) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", t.TempDir())
}

func TestClient_ErrorWhenNotConnected_Isolated(t *testing.T) {
	isolateFromLocalConfig(t)
	c, err := client()
	require.Error(t, err)
	assert.Nil(t, c)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestVerifyCmd_ClientErrorSurfaces(t *testing.T) {
	isolateFromLocalConfig(t)
	err := verifyCmd.RunE(verifyCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestExportCmd_ClientErrorSurfaces(t *testing.T) {
	isolateFromLocalConfig(t)
	flagSince, flagAfterID, flagLimit, flagAll, flagCSV = "", 0, 100, false, false
	err := exportCmd.RunE(exportCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestCheckpointCmd_ClientErrorSurfaces(t *testing.T) {
	isolateFromLocalConfig(t)
	err := checkpointCmd.RunE(checkpointCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestMigrateChainCmd_ClientErrorSurfaces(t *testing.T) {
	isolateFromLocalConfig(t)
	flagMigrateConfirm = false
	err := migrateChainCmd.RunE(migrateChainCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestRunLogsQuery_ClientErrorSurfaces(t *testing.T) {
	isolateFromLocalConfig(t)
	logEventType, logUserID, logProjectID, logActorType = "", 0, 0, ""
	flagSince, logUntil, logLimit = "", "", 50
	err := runLogsQuery()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestRunAuditSearch_ClientErrorSurfaces(t *testing.T) {
	isolateFromLocalConfig(t)
	resetSearchFlags()
	err := runAuditSearch()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// TestExport_CSV_SkipsUnparsableEvent exercises the json.Unmarshal error →
// continue branch in exportCmd's CSV path: a page event that is syntactically
// valid JSON (so it survives being captured as a json.RawMessage in
// exportPage.Events) but is not a JSON object (so it fails to decode into
// csvEventRow) must be silently skipped, while well-formed rows around it
// still make it into the CSV.
func TestExport_CSV_SkipsUnparsableEvent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"events":[
			{"id":1,"event_type":"secret.read","timestamp":"2026-06-19T10:00:00Z","actor":"alice","actor_type":"user","success":true,"description":"first"},
			42,
			{"id":2,"event_type":"secret.updated","timestamp":"2026-06-19T10:05:00Z","actor":"bob","actor_type":"user","success":true,"description":"second"}
		],"count":3,"next_cursor":null}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	var out, errOut bytes.Buffer
	exportCmd.SetOut(&out)
	exportCmd.SetErr(&errOut)
	flagSince, flagAfterID, flagLimit, flagAll, flagCSV = "", 0, 100, false, true
	defer func() { flagCSV = false }()
	require.NoError(t, exportCmd.RunE(exportCmd, nil))

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 3, "header + 2 valid rows; the unparsable middle event is skipped, not emitted as a blank/malformed row")
	assert.Contains(t, lines[1], "alice")
	assert.Contains(t, lines[1], "first")
	assert.Contains(t, lines[2], "bob")
	assert.Contains(t, lines[2], "second")
	// The unparsable event still counts toward the reported total (it was a
	// real event on the page, just not CSV-representable) — total is 3 events
	// even though only 2 CSV rows were written.
	assert.Contains(t, errOut.String(), "exported 3 event(s)")
}

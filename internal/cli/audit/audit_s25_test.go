// audit_s25_test.go — sprint-25 coverage additions for audit.go.
//
// Targets the remaining ~5-10% uncovered branches:
//   - verifyCmd: valid chain with checkpoint-reason note (line 137 else-if)
//   - verifyCmd: valid chain with anchor fields populated (lines 141-144)
//   - verifyCmd: server HTTP error
//   - checkpointCmd: response with AnchoredAt populated (lines 313-317)
//   - exportCmd: initial request carrying a non-zero flagAfterID
//   - exportCmd: flagSince forwarded as query param
//   - exportCmd: server HTTP error
//   - exportCmd: CSV row where secret_id is absent (nil → "")
//   - exportCmd: --all breaks on empty events page
//   - logsCmd: server HTTP error surfaced from runLogsQuery
//   - logsCmd: empty result ("No audit events match." path)
package audit

import (
	"bytes"
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// verifyCmd — additional text-output branches
// ---------------------------------------------------------------------------

// TestVerify_ValidWithCheckpointReason exercises the else-if branch at line 137:
// a valid chain that carries a checkpoint_reason note.
func TestVerify_ValidWithCheckpointReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"valid":true,"chained_events":5,"unchained_events":0,"head_hash":"abc","head_id":5,"checkpointed":true,"checkpoint_reason":"checkpoint covers 5 events"}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	flagJSON = false
	require.NoError(t, verifyCmd.RunE(verifyCmd, nil))
}

// TestVerify_ValidWithAnchor exercises the anchor-block output (lines 141-144):
// a valid, checkpointed chain that carries an external-notary receipt.
func TestVerify_ValidWithAnchor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"valid":true,"chained_events":10,"unchained_events":0,"head_hash":"deadbeef","head_id":10,"anchor_token":"dG9rZW4=","anchored_at":"2026-07-01T00:00:00Z","anchor_provider":"RFC3161/example-tsa"}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	flagJSON = false
	require.NoError(t, verifyCmd.RunE(verifyCmd, nil))
}

// TestVerify_ServerError exercises the c.Get error path in verifyCmd.
func TestVerify_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	flagJSON = false
	err := verifyCmd.RunE(verifyCmd, nil)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// checkpointCmd — response with AnchoredAt populated
// ---------------------------------------------------------------------------

// TestCheckpoint_WithAnchorFields exercises the anchored-at output block
// (lines 313-317 in checkpointCmd's RunE).
func TestCheckpoint_WithAnchorFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":3,"chained_events":15,"head_id":15,"head_hash":"ff00","key_version":"v2","anchored_at":"2026-07-10T00:00:00Z","anchor_provider":"RFC3161/example-tsa","anchor_token":"dG9rZW4="}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	require.NoError(t, checkpointCmd.RunE(checkpointCmd, nil))
}

// ---------------------------------------------------------------------------
// exportCmd — flagAfterID forwarded on the initial request
// ---------------------------------------------------------------------------

// TestExport_AfterIDForwarded verifies that a non-zero flagAfterID is sent as
// after_id on the very first request (not only on pagination continuations).
func TestExport_AfterIDForwarded(t *testing.T) {
	var gotAfterID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAfterID = r.URL.Query().Get("after_id")
		_, _ = w.Write([]byte(`{"data":{"events":[{"id":20,"event_type":"secret.read"}],"count":1,"next_cursor":null}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	var out, errOut bytes.Buffer
	exportCmd.SetOut(&out)
	exportCmd.SetErr(&errOut)
	flagSince, flagAfterID, flagLimit, flagAll, flagCSV = "", 10, 100, false, false
	defer func() { flagAfterID = 0 }()
	require.NoError(t, exportCmd.RunE(exportCmd, nil))

	assert.Equal(t, "10", gotAfterID, "initial request must carry the flagAfterID value as after_id")
	assert.Contains(t, out.String(), `"id":20`)
}

// ---------------------------------------------------------------------------
// exportCmd — flagSince forwarded as query param
// ---------------------------------------------------------------------------

// TestExport_SinceForwarded verifies that --since is sent on the request.
func TestExport_SinceForwarded(t *testing.T) {
	var gotSince string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSince = r.URL.Query().Get("since")
		_, _ = w.Write([]byte(`{"data":{"events":[{"id":5,"event_type":"secret.read"}],"count":1,"next_cursor":null}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	var out, errOut bytes.Buffer
	exportCmd.SetOut(&out)
	exportCmd.SetErr(&errOut)
	flagSince, flagAfterID, flagLimit, flagAll, flagCSV = "2026-06-01T00:00:00Z", 0, 100, false, false
	defer func() { flagSince = "" }()
	require.NoError(t, exportCmd.RunE(exportCmd, nil))

	assert.Equal(t, "2026-06-01T00:00:00Z", gotSince)
}

// ---------------------------------------------------------------------------
// exportCmd — server HTTP error
// ---------------------------------------------------------------------------

// TestExport_ServerError exercises the c.Get error path inside exportCmd.
func TestExport_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"audit.read permission required"}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	flagSince, flagAfterID, flagLimit, flagAll, flagCSV = "", 0, 100, false, false
	err := exportCmd.RunE(exportCmd, nil)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// exportCmd — CSV row where secret_id is absent (nil → "")
// ---------------------------------------------------------------------------

// TestExport_CSV_NilSecretID verifies that a missing secret_id in the event
// JSON is rendered as an empty string in the CSV column (uintPtrStr nil branch).
func TestExport_CSV_NilSecretID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// secret_id is intentionally absent from the JSON object.
		_, _ = w.Write([]byte(`{"data":{"events":[{"id":2,"event_type":"secret.read","timestamp":"2026-07-01T09:00:00Z","actor":"bob","actor_type":"user","user_id":3,"project_id":1,"ip_address":"192.168.1.1","success":true,"description":"read api-key"}],"count":1,"next_cursor":null}}`))
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
	require.Len(t, lines, 2, "header + one data row")

	r := csv.NewReader(strings.NewReader(lines[1]))
	fields, err := r.Read()
	require.NoError(t, err)

	// CSV columns: id, event_time, event_type, actor, actor_type, user_id, project_id, secret_id, ip_address, success, description
	const idxSecretID = 7
	assert.Equal(t, "", fields[idxSecretID], "absent secret_id must render as empty string")
}

// ---------------------------------------------------------------------------
// exportCmd — --all breaks on empty events page
// ---------------------------------------------------------------------------

// TestExport_AllBreaksOnEmptyPage verifies the third break condition:
// len(page.Events) == 0 terminates the --all loop even when next_cursor is set.
func TestExport_AllBreaksOnEmptyPage(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		// Return a non-nil next_cursor but zero events — loop must stop.
		_, _ = w.Write([]byte(`{"data":{"events":[],"count":0,"next_cursor":99}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	var out, errOut bytes.Buffer
	exportCmd.SetOut(&out)
	exportCmd.SetErr(&errOut)
	flagSince, flagAfterID, flagLimit, flagAll, flagCSV = "", 0, 100, true, false
	defer func() { flagAll = false }()
	require.NoError(t, exportCmd.RunE(exportCmd, nil))

	assert.Equal(t, 1, callCount, "--all must stop after one empty page even when next_cursor is non-nil")
	assert.Contains(t, errOut.String(), "exported 0 event(s)")
}

// ---------------------------------------------------------------------------
// logsCmd — server HTTP error
// ---------------------------------------------------------------------------

// TestLogsCmd_ServerError exercises the c.Get error path in runLogsQuery.
func TestLogsCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	logEventType, logUserID, logProjectID, logActorType = "", 0, 0, ""
	flagSince, logUntil, logLimit = "", "", 50
	err := logsCmd.RunE(logsCmd, nil)
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// logsCmd — empty result path
// ---------------------------------------------------------------------------

// TestLogsCmd_EmptyResult exercises the "No audit events match." branch.
func TestLogsCmd_EmptyResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"logs":[],"total":0}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	logEventType, logUserID, logProjectID, logActorType = "", 0, 0, ""
	flagSince, logUntil, logLimit = "", "", 50
	require.NoError(t, logsCmd.RunE(logsCmd, nil))
}

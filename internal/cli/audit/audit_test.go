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

func TestCommandWiring(t *testing.T) {
	names := map[string]bool{}
	for _, sub := range AuditCmd.Commands() {
		names[sub.Name()] = true
	}
	for _, want := range []string{"verify", "export"} {
		assert.True(t, names[want], "missing subcommand %q", want)
	}
	assert.NotNil(t, verifyCmd.Flags().Lookup("json"), "verify missing --json")
	for _, f := range []string{"since", "after-id", "limit", "all"} {
		assert.NotNilf(t, exportCmd.Flags().Lookup(f), "export missing --%s flag", f)
	}
}

// setRemote points the RemoteClient at a mock server.
func setRemote(t *testing.T, url string) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", url)
	t.Setenv("KEYORIX_TOKEN", "test-token")
}

func TestVerify_Valid(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"valid":true,"chained_events":42,"unchained_events":0,"head_hash":"abc123","head_id":42}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	var out bytes.Buffer
	verifyCmd.SetOut(&out)
	flagJSON = false
	require.NoError(t, verifyCmd.RunE(verifyCmd, nil))
	assert.Equal(t, "/api/v1/audit/verify", gotPath)
}

func TestVerify_CheckpointTruncationExitsNonZero(t *testing.T) {
	// A self-consistent chain walk (valid=false here) flagged by the signed
	// checkpoint must still surface as a non-zero exit with the checkpoint reason.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"valid":false,"chained_events":3,"unchained_events":0,"head_hash":"h","head_id":3,"checkpointed":true,"reason":"audit trail truncated below signed checkpoint #1: it certified 5 chained events, only 3 remain","checkpoint_reason":"audit trail truncated below signed checkpoint #1: it certified 5 chained events, only 3 remain"}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	flagJSON = false
	err := verifyCmd.RunE(verifyCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "truncated below signed checkpoint")
}

func TestVerify_BrokenExitsNonZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"valid":false,"chained_events":10,"unchained_events":0,"head_hash":"h","head_id":10,"first_broken_id":7,"reason":"hash mismatch at id 7"}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	flagJSON = false
	err := verifyCmd.RunE(verifyCmd, nil)
	require.Error(t, err, "a broken chain must surface as an error (non-zero exit)")
	assert.Contains(t, err.Error(), "FAILED")
	assert.Contains(t, err.Error(), "7")
}

func TestVerify_JSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"valid":true,"chained_events":3,"unchained_events":0,"head_hash":"deadbeef","head_id":3}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	var out bytes.Buffer
	verifyCmd.SetOut(&out)
	// --json prints to fmt.Println (real stdout); assert no error and correct anchor via a second path:
	flagJSON = true
	defer func() { flagJSON = false }()
	require.NoError(t, verifyCmd.RunE(verifyCmd, nil))
}

func TestExport_NDJSONAndCursorFollow(t *testing.T) {
	// Two pages: ids 1,2 (next_cursor 2) then id 3 (next_cursor null).
	var afterSeen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/audit/export", r.URL.Path)
		afterSeen = append(afterSeen, r.URL.Query().Get("after_id"))
		switch r.URL.Query().Get("after_id") {
		case "", "0":
			_, _ = w.Write([]byte(`{"data":{"events":[{"id":1,"event_type":"secret.read"},{"id":2,"event_type":"secret.read"}],"count":2,"next_cursor":2}}`))
		default:
			_, _ = w.Write([]byte(`{"data":{"events":[{"id":3,"event_type":"secret.updated"}],"count":1,"next_cursor":null}}`))
		}
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	var out, errOut bytes.Buffer
	exportCmd.SetOut(&out)
	exportCmd.SetErr(&errOut)
	flagSince, flagAfterID, flagLimit, flagAll = "", 0, 100, true
	require.NoError(t, exportCmd.RunE(exportCmd, nil))

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 3, "all 3 events emitted as NDJSON (one per line)")
	assert.Contains(t, lines[0], `"id":1`)
	assert.Contains(t, lines[2], `"id":3`)
	assert.Contains(t, errOut.String(), "caught up")
	assert.Contains(t, afterSeen, "2", "the cursor from page 1 was used to fetch page 2")
}

func TestExport_SinglePageCarriesCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "5", r.URL.Query().Get("limit"))
		_, _ = w.Write([]byte(`{"data":{"events":[{"id":9}],"count":1,"next_cursor":9}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	var out, errOut bytes.Buffer
	exportCmd.SetOut(&out)
	exportCmd.SetErr(&errOut)
	flagSince, flagAfterID, flagLimit, flagAll = "", 0, 5, false // no --all → one page only
	require.NoError(t, exportCmd.RunE(exportCmd, nil))

	assert.Equal(t, 1, strings.Count(strings.TrimSpace(out.String()), "\n")+1)
	assert.Contains(t, errOut.String(), "resume with --after-id 9")
}

func TestExport_Validation(t *testing.T) {
	t.Run("limit out of range", func(t *testing.T) {
		flagSince, flagAfterID, flagLimit, flagAll = "", 0, 5000, false
		err := exportCmd.RunE(exportCmd, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--limit must be between 1 and 1000")
	})
	t.Run("bad since", func(t *testing.T) {
		flagSince, flagLimit = "yesterday", 100
		err := exportCmd.RunE(exportCmd, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid --since")
	})
}

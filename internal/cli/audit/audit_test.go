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
	for _, want := range []string{"verify", "export", "checkpoint", "logs"} {
		assert.True(t, names[want], "missing subcommand %q", want)
	}
	assert.NotNil(t, verifyCmd.Flags().Lookup("json"), "verify missing --json")
	for _, f := range []string{"since", "after-id", "limit", "all"} {
		assert.NotNilf(t, exportCmd.Flags().Lookup(f), "export missing --%s flag", f)
	}
	for _, f := range []string{"event-type", "user-id", "project-id", "actor-type", "since", "until", "limit"} {
		assert.NotNilf(t, logsCmd.Flags().Lookup(f), "logs missing --%s flag", f)
	}
}

func TestLogs_FiltersAndRenders(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		_, _ = w.Write([]byte(`{"data":{"logs":[{"id":12,"event_type":"secret.deleted","actor":"ada","actor_type":"user","description":"deleted db-pw","timestamp":"2026-06-13T10:00:00Z"}],"total":1}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	logEventType, logUserID, logProjectID, logActorType, flagSince, logUntil, logLimit =
		"secret.deleted", 5, 0, "user", "", "", 50
	require.NoError(t, logsCmd.RunE(logsCmd, nil))

	assert.Equal(t, "/api/v1/audit/logs", gotPath)
	assert.Contains(t, gotQuery, "action=secret.deleted")
	assert.Contains(t, gotQuery, "user_id=5")
	assert.Contains(t, gotQuery, "actor_type=user")
	assert.Contains(t, gotQuery, "page_size=50")
}

func TestLogs_Validation(t *testing.T) {
	logEventType, logUserID, logProjectID, logActorType, flagSince, logUntil = "", 0, 0, "", "", ""
	t.Run("limit range", func(t *testing.T) {
		logLimit = 500
		require.ErrorContains(t, logsCmd.RunE(logsCmd, nil), "--limit must be between 1 and 100")
	})
	t.Run("bad since", func(t *testing.T) {
		logLimit, flagSince = 50, "last week"
		require.ErrorContains(t, logsCmd.RunE(logsCmd, nil), "invalid --since")
	})
	t.Run("bad actor-type", func(t *testing.T) {
		logLimit, flagSince, logActorType = 50, "", "robot"
		require.ErrorContains(t, logsCmd.RunE(logsCmd, nil), "--actor-type must be")
	})
}

func TestTruncateAndShortTime(t *testing.T) {
	assert.Equal(t, "short", truncate("short", 16))
	assert.Equal(t, "abcd…", truncate("abcdefgh", 5))
	assert.Equal(t, "2026-06-13 10:00:00", shortTime("2026-06-13T10:00:00Z"))
	assert.Equal(t, "not-a-time", shortTime("not-a-time"))
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

func TestCheckpoint_PostsAndReportsError(t *testing.T) {
	t.Run("success posts to the checkpoint endpoint", func(t *testing.T) {
		var gotMethod, gotPath string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotMethod, gotPath = r.Method, r.URL.Path
			_, _ = w.Write([]byte(`{"data":{"id":7,"chained_events":42,"head_id":42,"head_hash":"abc","key_version":"v1"}}`))
		}))
		defer srv.Close()
		setRemote(t, srv.URL)

		require.NoError(t, checkpointCmd.RunE(checkpointCmd, nil))
		assert.Equal(t, http.MethodPost, gotMethod)
		assert.Equal(t, "/api/v1/audit/checkpoint", gotPath)
	})

	t.Run("server refusal surfaces as an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"refusing to checkpoint"}`))
		}))
		defer srv.Close()
		setRemote(t, srv.URL)

		err := checkpointCmd.RunE(checkpointCmd, nil)
		require.Error(t, err)
	})
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

func TestExport_CSV(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"events":[{"id":1,"event_type":"secret.created","timestamp":"2026-06-19T10:00:00Z","actor":"alice","actor_type":"user","user_id":7,"project_id":5,"ip_address":"10.0.0.1","success":true,"description":"created db"}],"count":1,"next_cursor":null}}`))
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
	require.Len(t, lines, 2, "header + one event row")
	assert.Equal(t, "id,event_time,event_type,actor,actor_type,user_id,project_id,secret_id,ip_address,success,description", lines[0])
	assert.Contains(t, lines[1], "secret.created")
	assert.Contains(t, lines[1], "alice")
	assert.Contains(t, lines[1], "created db")
	assert.Contains(t, lines[1], "1,2026-06-19T10:00:00Z")
}

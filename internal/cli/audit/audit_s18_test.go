// audit_s18_test.go — sprint-18 coverage additions for audit.go.
// Targets uncovered branches: client() error path, printAuditLogTable,
// uintPtrStr, buildAuditLogQuery remaining branches, truncate edge cases.
// All tests avoid httptest.NewServer (sandbox networking restriction);
// they either exercise pure functions or force the "not connected" error path
// by ensuring KEYORIX_SERVER and KEYORIX_TOKEN env vars are absent.
package audit

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// client() — "not connected" error path
// ---------------------------------------------------------------------------

// clearRemote unsets the env vars used by ResolveRemote so that client()
// returns the "not connected" error. It restores the original values via
// t.Setenv (which calls t.Cleanup internally).
func clearRemote(t *testing.T) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
}

// TestClient_ErrorWhenNotConnected exercises the client() helper's error branch.
func TestClient_ErrorWhenNotConnected(t *testing.T) {
	clearRemote(t)
	c, err := client()
	require.Error(t, err, "client() must return an error when no server is configured")
	assert.Nil(t, c)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// ---------------------------------------------------------------------------
// Command RunE — "not connected" error paths (no network needed)
// ---------------------------------------------------------------------------

func TestVerifyCmd_NoClient(t *testing.T) {
	clearRemote(t)
	err := verifyCmd.RunE(verifyCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestExportCmd_NoClient(t *testing.T) {
	clearRemote(t)
	flagSince, flagAfterID, flagLimit, flagAll, flagCSV = "", 0, 100, false, false
	err := exportCmd.RunE(exportCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestCheckpointCmd_NoClient(t *testing.T) {
	clearRemote(t)
	err := checkpointCmd.RunE(checkpointCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

func TestLogsCmd_NoClient(t *testing.T) {
	clearRemote(t)
	logEventType, logUserID, logProjectID, logActorType = "", 0, 0, ""
	flagSince, logUntil, logLimit = "", "", 50
	err := logsCmd.RunE(logsCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected to a server")
}

// ---------------------------------------------------------------------------
// uintPtrStr — pure function, nil and non-nil branches
// ---------------------------------------------------------------------------

func TestUintPtrStr_Nil(t *testing.T) {
	assert.Equal(t, "", uintPtrStr(nil), "nil pointer should return empty string")
}

func TestUintPtrStr_NonNil(t *testing.T) {
	v := uint(42)
	assert.Equal(t, "42", uintPtrStr(&v))
	zero := uint(0)
	assert.Equal(t, "0", uintPtrStr(&zero))
}

// ---------------------------------------------------------------------------
// truncate — n <= 1 edge cases not covered by existing tests
// ---------------------------------------------------------------------------

func TestTruncate_ZeroWidth(t *testing.T) {
	// n=0 enters the n <= 1 branch and returns s[:0] = "".
	assert.Equal(t, "", truncate("hello", 0))
}

func TestTruncate_OneWidth(t *testing.T) {
	// n=1 also enters the n <= 1 branch; result is the first byte.
	assert.Equal(t, "h", truncate("hello", 1))
}

func TestTruncate_ExactLength(t *testing.T) {
	// len(s) == n → no truncation, no ellipsis.
	assert.Equal(t, "abc", truncate("abc", 3))
}

// ---------------------------------------------------------------------------
// buildAuditLogQuery — additional branch coverage
// ---------------------------------------------------------------------------

func TestBuildAuditLogQuery_BadUntil(t *testing.T) {
	logLimit = 50
	flagSince = ""
	logUntil = "not-a-timestamp"
	logActorType = ""
	logEventType, logUserID, logProjectID = "", 0, 0

	_, err := buildAuditLogQuery()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --until")

	logUntil = "" // restore
}

func TestBuildAuditLogQuery_AllFilters(t *testing.T) {
	// Valid call with every optional filter populated: logProjectID, logUntil,
	// each recognised actor type, flagSince.
	actorTypes := []string{"machine_identity", "system", "user", ""}
	for _, at := range actorTypes {
		t.Run("actor_type="+at, func(t *testing.T) {
			logEventType = "secret.read"
			logUserID = 3
			logProjectID = 7
			logActorType = at
			flagSince = "2026-01-01T00:00:00Z"
			logUntil = "2026-12-31T23:59:59Z"
			logLimit = 25

			q, err := buildAuditLogQuery()
			require.NoError(t, err)
			assert.Equal(t, "25", q.Get("page_size"))
			assert.Equal(t, "secret.read", q.Get("action"))
			assert.Equal(t, "3", q.Get("user_id"))
			assert.Equal(t, "7", q.Get("project_id"))
			assert.Equal(t, "2026-01-01T00:00:00Z", q.Get("start_time"))
			assert.Equal(t, "2026-12-31T23:59:59Z", q.Get("end_time"))
			if at != "" {
				assert.Equal(t, at, q.Get("actor_type"))
			} else {
				assert.Empty(t, q.Get("actor_type"))
			}
		})
	}

	// Restore defaults.
	logEventType, logUserID, logProjectID, logActorType = "", 0, 0, ""
	flagSince, logUntil, logLimit = "", "", 50
}

func TestBuildAuditLogQuery_MinimalValid(t *testing.T) {
	// No optional flags — just the minimum limit.
	logEventType, logUserID, logProjectID, logActorType = "", 0, 0, ""
	flagSince, logUntil = "", ""
	logLimit = 1

	q, err := buildAuditLogQuery()
	require.NoError(t, err)
	assert.Equal(t, "1", q.Get("page_size"))
	assert.Empty(t, q.Get("action"))
	assert.Empty(t, q.Get("user_id"))
	assert.Empty(t, q.Get("project_id"))
	assert.Empty(t, q.Get("actor_type"))
	assert.Empty(t, q.Get("start_time"))
	assert.Empty(t, q.Get("end_time"))

	logLimit = 50 // restore
}

// ---------------------------------------------------------------------------
// printAuditLogTable — direct call, no network needed
// ---------------------------------------------------------------------------

func TestPrintAuditLogTable_NoImpersonation(t *testing.T) {
	logs := []logEntry{
		{
			ID:          1,
			EventType:   "secret.read",
			Actor:       "alice",
			ActorType:   "user",
			Description: "read my-secret",
			Timestamp:   "2026-07-01T10:00:00Z",
		},
		{
			ID:          2,
			EventType:   "secret.deleted",
			Actor:       "bob",
			ActorType:   "user",
			Description: "deleted old-pw",
			Timestamp:   "2026-07-01T11:00:00Z",
		},
	}
	// printAuditLogTable writes to real stdout; we verify it does not panic.
	printAuditLogTable(logs, 2)
}

func TestPrintAuditLogTable_WithImpersonation(t *testing.T) {
	logs := []logEntry{
		{
			ID:             3,
			EventType:      "secret.created",
			Actor:          "user-target",
			ActorType:      "user",
			Description:    "impersonated write",
			Timestamp:      "2026-07-01T12:00:00Z",
			Impersonation:  true,
			ImpersonatedBy: "admin",
		},
	}
	// Exercises the impersonation branch: actor is set to
	// ImpersonatedBy + "→" + Actor before formatting.
	printAuditLogTable(logs, 1)
}

func TestPrintAuditLogTable_LongActorAndBadTimestamp(t *testing.T) {
	logs := []logEntry{
		{
			ID:            4,
			EventType:     "system.login",
			Actor:         strings.Repeat("a", 30), // long actor name → triggers truncate
			ActorType:     "machine_identity",
			Description:   "",
			Timestamp:     "not-a-time", // exercises shortTime fallback (returns raw string)
			Impersonation: false,
		},
	}
	printAuditLogTable(logs, 1)
}

// ---------------------------------------------------------------------------
// runLogsQuery — validation error short-circuits before network
// ---------------------------------------------------------------------------

func TestRunLogsQuery_ValidationErrorShortCircuits(t *testing.T) {
	// Set an invalid limit so buildAuditLogQuery returns an error before
	// client() is ever called — no network required.
	logLimit = 0
	logEventType, logUserID, logProjectID, logActorType = "", 0, 0, ""
	flagSince, logUntil = "", ""

	err := runLogsQuery()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--limit must be between 1 and 100")

	logLimit = 50 // restore
}

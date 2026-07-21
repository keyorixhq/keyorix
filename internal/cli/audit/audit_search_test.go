// audit_search_test.go — tests for the `keyorix audit search` command.
// Covers buildAuditSearchQuery, runAuditSearch, and printAuditSearchTable.
package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── buildAuditSearchQuery validation ─────────────────────────────────────────

func TestBuildAuditSearchQuery_InvalidLimit(t *testing.T) {
	resetSearchFlags()
	searchLimit = 0
	_, err := buildAuditSearchQuery()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--limit must be between 1 and 1000")
}

func TestBuildAuditSearchQuery_LimitOverMax(t *testing.T) {
	resetSearchFlags()
	searchLimit = 1001
	_, err := buildAuditSearchQuery()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--limit must be between 1 and 1000")
}

func TestBuildAuditSearchQuery_InvalidSince(t *testing.T) {
	resetSearchFlags()
	searchSince = "not-a-time"
	_, err := buildAuditSearchQuery()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --since")
}

func TestBuildAuditSearchQuery_InvalidUntil(t *testing.T) {
	resetSearchFlags()
	searchUntil = "last-week"
	_, err := buildAuditSearchQuery()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --until")
}

func TestBuildAuditSearchQuery_InvalidSuccess(t *testing.T) {
	resetSearchFlags()
	searchSuccess = "maybe"
	_, err := buildAuditSearchQuery()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--success must be true or false")
}

func TestBuildAuditSearchQuery_AllFilters(t *testing.T) {
	resetSearchFlags()
	searchActor = "alice"
	searchUserID = 5
	searchProjectID = 2
	searchAction = "secret.read"
	searchResourceType = "secret"
	searchResourceID = 10
	searchIP = "10.0.0.1"
	searchSuccess = "true"
	searchSince = "2026-01-01T00:00:00Z"
	searchUntil = "2026-12-31T00:00:00Z"
	searchLimit = 50
	searchOffset = 100

	q, err := buildAuditSearchQuery()
	require.NoError(t, err)
	assert.Equal(t, "alice", q.Get("actor"))
	assert.Equal(t, "5", q.Get("user_id"))
	assert.Equal(t, "2", q.Get("project_id"))
	assert.Equal(t, "secret.read", q.Get("action"))
	assert.Equal(t, "secret", q.Get("resource_type"))
	assert.Equal(t, "10", q.Get("resource_id"))
	assert.Equal(t, "10.0.0.1", q.Get("ip"))
	assert.Equal(t, "true", q.Get("success"))
	assert.Equal(t, "2026-01-01T00:00:00Z", q.Get("since"))
	assert.Equal(t, "2026-12-31T00:00:00Z", q.Get("until"))
	assert.Equal(t, "50", q.Get("limit"))
	assert.Equal(t, "100", q.Get("offset"))
}

func TestBuildAuditSearchQuery_NoOptionalFilters(t *testing.T) {
	resetSearchFlags()
	q, err := buildAuditSearchQuery()
	require.NoError(t, err)
	assert.Equal(t, "100", q.Get("limit"))
	// Optional filters must not appear when not set.
	assert.Empty(t, q.Get("actor"))
	assert.Empty(t, q.Get("user_id"))
	assert.Empty(t, q.Get("project_id"))
	assert.Empty(t, q.Get("action"))
	assert.Empty(t, q.Get("resource_type"))
	assert.Empty(t, q.Get("resource_id"))
	assert.Empty(t, q.Get("ip"))
	assert.Empty(t, q.Get("success"))
	assert.Empty(t, q.Get("since"))
	assert.Empty(t, q.Get("until"))
	assert.Empty(t, q.Get("offset"))
}

func TestBuildAuditSearchQuery_ValidSuccessFalse(t *testing.T) {
	resetSearchFlags()
	searchSuccess = "false"
	q, err := buildAuditSearchQuery()
	require.NoError(t, err)
	assert.Equal(t, "false", q.Get("success"))
}

// ── runAuditSearch ────────────────────────────────────────────────────────────

func TestRunAuditSearch_WithResults(t *testing.T) {
	resetSearchFlags()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/audit/search", r.URL.Path)
		_, _ = w.Write([]byte(`{"data":{"events":[{"id":1,"event_type":"secret.read","description":"test","event_time":"2026-06-01T10:00:00Z","ip_address":"10.0.0.1","actor_type":"user"}],"total":1}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	require.NoError(t, runAuditSearch())
}

func TestRunAuditSearch_EmptyResult(t *testing.T) {
	resetSearchFlags()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"events":[],"total":0}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	require.NoError(t, runAuditSearch())
}

func TestRunAuditSearch_ServerError(t *testing.T) {
	resetSearchFlags()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"db gone"}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	err := runAuditSearch()
	require.Error(t, err)
}

func TestRunAuditSearch_NoRemote(t *testing.T) {
	resetSearchFlags()
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	err := runAuditSearch()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestRunAuditSearch_InvalidLimit(t *testing.T) {
	resetSearchFlags()
	searchLimit = 9999
	err := searchCmd.RunE(searchCmd, nil)
	require.Error(t, err)
}

// ── printAuditSearchTable ─────────────────────────────────────────────────────

func TestPrintAuditSearchTable_Renders(t *testing.T) {
	events := []searchEvent{
		{ID: 1, EventType: "secret.read", Description: "read a secret", EventTime: "2026-06-01T10:00:00Z", IPAddress: "10.0.0.1", ActorType: "user"},
		{ID: 2, EventType: "user.login.very_long_event_type_that_exceeds_column", Description: "long event", EventTime: "not-a-time", IPAddress: "", ActorType: "machine_identity_type_that_is_long"},
	}
	// printAuditSearchTable writes to stdout; just verify it does not panic.
	printAuditSearchTable(events, 42)
}

// ── command wiring ────────────────────────────────────────────────────────────

func TestSearchCommandWired(t *testing.T) {
	names := map[string]bool{}
	for _, sub := range AuditCmd.Commands() {
		names[sub.Name()] = true
	}
	assert.True(t, names["search"], "search subcommand must be registered")
}

func TestSearchCommandFlags(t *testing.T) {
	for _, f := range []string{
		"actor", "user-id", "project-id", "action", "resource-type",
		"resource-id", "ip", "success", "since", "until", "limit", "offset",
	} {
		assert.NotNilf(t, searchCmd.Flags().Lookup(f), "search missing --%s flag", f)
	}
}

// resetSearchFlags resets all package-level search flag variables to their
// zero/default values before each test, preventing cross-test pollution.
func resetSearchFlags() {
	searchActor = ""
	searchUserID = 0
	searchProjectID = 0
	searchAction = ""
	searchResourceType = ""
	searchResourceID = 0
	searchIP = ""
	searchSuccess = ""
	searchSince = ""
	searchUntil = ""
	searchLimit = 100
	searchOffset = 0
}

package anomalies

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// escalationStub starts a stub server and returns a configured RemoteClient.
func escalationStub(t *testing.T, handle http.HandlerFunc) (*common.RemoteClient, func()) {
	t.Helper()
	srv := httptest.NewServer(handle)
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-tok")
	rc, ok := common.NewRemoteClient()
	require.True(t, ok)
	return rc, srv.Close
}

// ── list ──────────────────────────────────────────────────────────────────────

func TestRunEscalationListRemote_Empty(t *testing.T) {
	rc, done := escalationStub(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/alert-escalation-policies", r.URL.Path)
		_, _ = w.Write([]byte(`{"data":{"policies":[]}}`))
	})
	defer done()

	require.NoError(t, runEscalationListRemote(rc))
}

func TestRunEscalationListRemote_WithPolicies(t *testing.T) {
	rc, done := escalationStub(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"policies":[
			{"id":1,"name":"on-call","min_severity":"high","escalate_after_minutes":30,"channel_ids":"1,2","enabled":true},
			{"id":2,"name":"disabled-pol","min_severity":"low","escalate_after_minutes":60,"channel_ids":"3","enabled":false}
		]}}`))
	})
	defer done()

	require.NoError(t, runEscalationListRemote(rc))
}

func TestRunEscalationListRemote_ServerError(t *testing.T) {
	rc, done := escalationStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer done()

	err := runEscalationListRemote(rc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestRunEscalationList_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	err := runEscalationList(escalationListCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// ── create ────────────────────────────────────────────────────────────────────

func TestRunEscalationCreateRemote(t *testing.T) {
	var gotBody map[string]any
	rc, done := escalationStub(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/v1/alert-escalation-policies", r.URL.Path)
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = w.Write([]byte(`{"data":{"id":5,"name":"alert-pol","min_severity":"high","escalate_after_minutes":30,"channel_ids":"1","enabled":true}}`))
	})
	defer done()

	orig := flagEscalationName
	defer func() { flagEscalationName = orig }()
	flagEscalationName = "alert-pol"
	flagEscalationMinSeverity = "high"
	flagEscalationAfterMinutes = 30
	flagEscalationChannels = "1"

	require.NoError(t, runEscalationCreateRemote(rc))
	assert.Equal(t, "alert-pol", gotBody["name"])
	assert.Equal(t, "high", gotBody["min_severity"])
}

func TestRunEscalationCreate_MissingName(t *testing.T) {
	orig := flagEscalationName
	defer func() { flagEscalationName = orig }()
	flagEscalationName = ""

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	err := runEscalationCreate(escalationCreateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--name is required")
}

func TestRunEscalationCreate_NotConnected(t *testing.T) {
	orig := flagEscalationName
	defer func() { flagEscalationName = orig }()
	flagEscalationName = "some-policy"

	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	err := runEscalationCreate(escalationCreateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestRunEscalationCreateRemote_ServerError(t *testing.T) {
	rc, done := escalationStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	})
	defer done()

	orig := flagEscalationName
	defer func() { flagEscalationName = orig }()
	flagEscalationName = "pol"

	err := runEscalationCreateRemote(rc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "400")
}

// ── delete ────────────────────────────────────────────────────────────────────

func TestRunEscalationDeleteRemote(t *testing.T) {
	var gotPath string
	rc, done := escalationStub(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		assert.Equal(t, http.MethodDelete, r.Method)
		w.WriteHeader(http.StatusNoContent)
	})
	defer done()

	require.NoError(t, runEscalationDeleteRemote(rc, 42))
	assert.Equal(t, "/api/v1/alert-escalation-policies/42", gotPath)
}

func TestRunEscalationDeleteRemote_ServerError(t *testing.T) {
	rc, done := escalationStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer done()

	err := runEscalationDeleteRemote(rc, 99)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestRunEscalationDelete_InvalidID(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "http://localhost:9")
	t.Setenv("KEYORIX_TOKEN", "tok")

	err := runEscalationDelete(escalationDeleteCmd, []string{"not-a-number"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid policy ID")
}

func TestRunEscalationDelete_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	err := runEscalationDelete(escalationDeleteCmd, []string{"5"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// ── run ───────────────────────────────────────────────────────────────────────

func TestRunEscalationRunRemote(t *testing.T) {
	var gotPath string
	rc, done := escalationStub(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		assert.Equal(t, http.MethodPost, r.Method)
		_, _ = w.Write([]byte(`{"data":{"evaluated":10,"escalated":3,"skipped":7}}`))
	})
	defer done()

	require.NoError(t, runEscalationRunRemote(rc))
	assert.Equal(t, "/api/v1/system/admin/jobs/run-alert-escalation", gotPath)
}

func TestRunEscalationRunRemote_ServerError(t *testing.T) {
	rc, done := escalationStub(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	defer done()

	err := runEscalationRunRemote(rc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestRunEscalationRun_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	err := runEscalationRun(escalationRunCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

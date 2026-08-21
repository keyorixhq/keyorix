package anomalies

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunEscalationList_Connected exercises the top-level runEscalationList's
// success branch (RunE -> NewRemoteClient ok -> runEscalationListRemote),
// which the existing tests only reach indirectly through runEscalationListRemote.
func TestRunEscalationList_Connected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"policies":[]}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	require.NoError(t, runEscalationList(escalationListCmd, nil))
}

// TestRunEscalationCreate_Connected exercises the top-level runEscalationCreate's
// success branch, requiring both a non-empty --name and a connected server.
func TestRunEscalationCreate_Connected(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"id":9,"name":"conn-pol","min_severity":"high","escalate_after_minutes":30,"channel_ids":"1","enabled":true}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	orig := flagEscalationName
	defer func() { flagEscalationName = orig }()
	flagEscalationName = "conn-pol"
	flagEscalationMinSeverity = "high"
	flagEscalationAfterMinutes = 30
	flagEscalationChannels = "1"

	require.NoError(t, runEscalationCreate(escalationCreateCmd, nil))
	assert.Equal(t, "/api/v1/alert-escalation-policies", gotPath)
}

// TestRunEscalationDelete_Connected exercises the top-level runEscalationDelete's
// success branch, requiring both a valid numeric ID and a connected server.
func TestRunEscalationDelete_Connected(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	require.NoError(t, runEscalationDelete(escalationDeleteCmd, []string{"11"}))
	assert.Equal(t, "/api/v1/alert-escalation-policies/11", gotPath)
}

// TestRunEscalationRun_Connected exercises the top-level runEscalationRun's
// success branch.
func TestRunEscalationRun_Connected(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"data":{"evaluated":1,"escalated":0,"skipped":1}}`))
	}))
	defer srv.Close()

	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	require.NoError(t, runEscalationRun(escalationRunCmd, nil))
	assert.Equal(t, "/api/v1/system/admin/jobs/run-alert-escalation", gotPath)
}

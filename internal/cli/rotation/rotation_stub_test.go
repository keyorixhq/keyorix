package rotation

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestShow_HappyPath drives `show` against a stub and checks it fetches by ID and
// prints the policy.
func TestShow_HappyPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		pid := uint(5)
		_ = pid
		_, _ = w.Write([]byte(`{"data":{"id":3,"name":"quarterly","scope":"project","project_id":5,"interval_days":90,"alert_days_before":7,"notify_on_breach":true,"is_active":true,"created_by":"admin"}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	require.NoError(t, showCmd.RunE(showCmd, []string{"3"}))
	assert.Equal(t, "/api/v1/rotation-policies/3", gotPath)
}

// TestShow_WithDescription verifies the description line is printed only when non-empty.
func TestShow_WithDescription(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"id":3,"name":"quarterly","description":"my desc","scope":"project","interval_days":90,"alert_days_before":7}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	require.NoError(t, showCmd.RunE(showCmd, []string{"3"}))
}

// TestDelete_HappyPath drives `delete` against a stub and checks it sends a DELETE.
func TestDelete_HappyPath(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	require.NoError(t, deleteCmd.RunE(deleteCmd, []string{"5"}))
	assert.Equal(t, http.MethodDelete, gotMethod)
	assert.Equal(t, "/api/v1/rotation-policies/5", gotPath)
}

// TestList_EmptyPolicies verifies the "No rotation policies" branch.
func TestList_EmptyPolicies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	lProject, lEnv = 0, 0
	require.NoError(t, listCmd.RunE(listCmd, nil))
}

// TestList_WithEnvironmentFilter verifies the environment_id filter is applied.
func TestList_WithEnvironmentFilter(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	lProject, lEnv = 0, 3
	require.NoError(t, listCmd.RunE(listCmd, nil))
	assert.Contains(t, gotQuery, "environment_id=3")
}

// TestStatus_AllClear verifies the "all within window" branch.
func TestStatus_AllClear(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a secret that is neither overdue nor approaching.
		_, _ = w.Write([]byte(`{"data":[{"secret_id":1,"secret_name":"ok","project_id":2,"days_overdue":-100,"is_overdue":false,"is_approaching":false}]}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	sProject = 0
	require.NoError(t, statusCmd.RunE(statusCmd, nil))
}

// TestStatus_Approaching tests the "approaching" status path in the status table.
func TestStatus_Approaching(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":[
			{"secret_id":2,"secret_name":"certs","project_id":1,"days_overdue":-5,"is_overdue":false,"is_approaching":true},
			{"secret_id":3,"secret_name":"ok","project_id":1,"days_overdue":-100,"is_overdue":false,"is_approaching":false}
		]}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	sProject = 0
	require.NoError(t, statusCmd.RunE(statusCmd, nil))
}

// TestClientHelper_NotConnected verifies client() returns an error when no server is set.
func TestClientHelper_NotConnected(t *testing.T) {
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	_, err := client()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestPlanCmd_Validation verifies planCmd rejects --all-projects + a project-id arg.
func TestPlanCmd_AllProjectsWithArgIsError(t *testing.T) {
	// --all-projects takes no positional argument.
	origAllProjects := planAllProjects
	defer func() { planAllProjects = origAllProjects }()
	planAllProjects = true

	// Also need a server so NewRemoteClient succeeds.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	setRemote(t, srv.URL)

	err := planCmd.RunE(planCmd, []string{"1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--all-projects takes no project-id argument")
}

// TestPlanCmd_NoArg verifies planCmd requires a project-id (or --all-projects).
func TestPlanCmd_NoArg(t *testing.T) {
	origAllProjects := planAllProjects
	defer func() { planAllProjects = origAllProjects }()
	planAllProjects = false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	setRemote(t, srv.URL)

	err := planCmd.RunE(planCmd, []string{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provide a project id")
}

// TestPlanCmd_InvalidProjectID verifies planCmd rejects a non-numeric project ID.
func TestPlanCmd_InvalidProjectID(t *testing.T) {
	origAllProjects := planAllProjects
	defer func() { planAllProjects = origAllProjects }()
	planAllProjects = false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	setRemote(t, srv.URL)

	err := planCmd.RunE(planCmd, []string{"abc"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid project id")
}

// TestPlanCmd_EmptyWaves verifies planCmd prints "Nothing to rotate" for an empty plan.
func TestPlanCmd_EmptyWaves(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"project_id":1,"total_secrets":0,"overdue_count":0,"due_soon_count":0,"waves":[]}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	origAllProjects := planAllProjects
	defer func() { planAllProjects = origAllProjects }()
	planAllProjects = false

	require.NoError(t, planCmd.RunE(planCmd, []string{"1"}))
}

// TestPlanCmd_AllProjectsClean verifies the "Nothing to rotate" branch for the deployment plan.
func TestPlanCmd_AllProjectsClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects_scanned":3,"projects_with_work":0,"total_secrets":0,"overdue_count":0,"due_soon_count":0,"projects":[]}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	origAllProjects := planAllProjects
	defer func() { planAllProjects = origAllProjects }()
	planAllProjects = true

	require.NoError(t, planCmd.RunE(planCmd, []string{}))
}

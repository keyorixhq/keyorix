// rotation_g80_test.go — coverage sweep for the remaining branches in rotation.go,
// order.go and plan.go: per-command "not connected" and server-error paths for
// list/create/show/delete/status, orderCmd/planCmd not-connected and fetch-error
// paths driven through RunE (not just the split-out fetch* helpers), and the
// create body's optional-field branches (description, environment-id).
package rotation

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// notConnected points KEYORIX_SERVER/TOKEN at nothing and isolates config
// discovery so common.NewRemoteClient() (and client()) reliably reports "not
// connected", mirroring TestClientHelper_NotConnected in rotation_extra_test.go.
func notConnected(t *testing.T) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", "")
	t.Setenv("KEYORIX_TOKEN", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
}

func TestListCmd_NotConnected(t *testing.T) {
	notConnected(t)
	err := listCmd.RunE(listCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestListCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	lProject, lEnv = 0, 0
	err := listCmd.RunE(listCmd, nil)
	require.Error(t, err)
}

func TestCreateCmd_NotConnected(t *testing.T) {
	notConnected(t)
	cName, cScope, cInterval, cProject, cEnv, cDesc = "x", "project", 30, 5, 0, ""
	err := createCmd.RunE(createCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestCreateCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	cName, cScope, cInterval, cProject, cEnv, cDesc = "x", "project", 30, 5, 0, ""
	err := createCmd.RunE(createCmd, nil)
	require.Error(t, err)
}

// TestCreateCmd_DescriptionAndEnvironmentInBody verifies the create body carries
// "description" only when --description is set, and carries "environment_id"
// (not "project_id") for environment-scoped policies.
func TestCreateCmd_DescriptionAndEnvironmentInBody(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(`{"data":{"ID":9,"Name":"env-policy","Scope":"environment","EnvironmentID":4,"IntervalDays":14,"AlertDaysBefore":3}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	cName, cScope, cProject, cEnv, cInterval, cAlert, cNotify, cDesc =
		"env-policy", "environment", 0, 4, 14, 3, false, "rotate the env creds"
	require.NoError(t, createCmd.RunE(createCmd, nil))

	assert.Equal(t, "rotate the env creds", gotBody["description"])
	assert.Equal(t, float64(4), gotBody["environment_id"])
	assert.NotContains(t, gotBody, "project_id")
}

func TestShowCmd_NotConnected(t *testing.T) {
	notConnected(t)
	err := showCmd.RunE(showCmd, []string{"3"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestShowCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	err := showCmd.RunE(showCmd, []string{"3"})
	require.Error(t, err)
}

func TestDeleteCmd_NotConnected(t *testing.T) {
	notConnected(t)
	err := deleteCmd.RunE(deleteCmd, []string{"3"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestDeleteCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	err := deleteCmd.RunE(deleteCmd, []string{"3"})
	require.Error(t, err)
}

func TestStatusCmd_NotConnected(t *testing.T) {
	notConnected(t)
	sProject = 0
	err := statusCmd.RunE(statusCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

func TestStatusCmd_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	sProject = 0
	err := statusCmd.RunE(statusCmd, nil)
	require.Error(t, err)
}

// TestOrderCmd_InvalidProjectID verifies orderCmd's own id-parsing branch
// (distinct from planCmd's, and from the direct fetchRotationOrder tests which
// never exercise argument parsing).
func TestOrderCmd_InvalidProjectID(t *testing.T) {
	err := orderCmd.RunE(orderCmd, []string{"abc"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid project id")

	err = orderCmd.RunE(orderCmd, []string{"0"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid project id")
}

func TestOrderCmd_NotConnected(t *testing.T) {
	notConnected(t)
	err := orderCmd.RunE(orderCmd, []string{"1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestOrderCmd_FetchError verifies the RunE-level error branch after
// fetchRotationOrder fails (distinct from calling fetchRotationOrder directly).
func TestOrderCmd_FetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	err := orderCmd.RunE(orderCmd, []string{"1"})
	require.Error(t, err)
}

func TestPlanCmd_NotConnected(t *testing.T) {
	notConnected(t)
	origAllProjects := planAllProjects
	defer func() { planAllProjects = origAllProjects }()
	planAllProjects = false

	err := planCmd.RunE(planCmd, []string{"1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not connected")
}

// TestPlanCmd_FetchError verifies the RunE-level error branch after
// fetchRotationPlan fails for a single project.
func TestPlanCmd_FetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	origAllProjects := planAllProjects
	defer func() { planAllProjects = origAllProjects }()
	planAllProjects = false

	err := planCmd.RunE(planCmd, []string{"1"})
	require.Error(t, err)
}

// TestPlanCmd_AllProjectsFetchError verifies the RunE-level error branch after
// fetchDeploymentRotationPlan fails.
func TestPlanCmd_AllProjectsFetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	origAllProjects := planAllProjects
	defer func() { planAllProjects = origAllProjects }()
	planAllProjects = true

	err := planCmd.RunE(planCmd, []string{})
	require.Error(t, err)
}

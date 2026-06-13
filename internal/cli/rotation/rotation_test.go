package rotation

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommandWiring(t *testing.T) {
	names := map[string]bool{}
	for _, sub := range RotationCmd.Commands() {
		names[sub.Name()] = true
	}
	for _, want := range []string{"list", "create", "show", "delete", "status"} {
		assert.True(t, names[want], "missing subcommand %q", want)
	}
	assert.Contains(t, RotationCmd.Aliases, "rotation-policy")
	for _, f := range []string{"name", "scope", "interval-days", "project-id", "environment-id", "alert-days-before"} {
		assert.NotNilf(t, createCmd.Flags().Lookup(f), "create missing --%s", f)
	}
}

func setRemote(t *testing.T, url string) {
	t.Helper()
	t.Setenv("KEYORIX_SERVER", url)
	t.Setenv("KEYORIX_TOKEN", "test-token")
}

func TestCreate_PostsBodyAndScope(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		// Server emits PascalCase keys (model has no json tags); decode is case-insensitive.
		_, _ = w.Write([]byte(`{"data":{"ID":3,"Name":"db-30d","Scope":"project","ProjectID":5,"IntervalDays":30,"AlertDaysBefore":7}}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	cName, cScope, cProject, cEnv, cInterval, cAlert, cNotify, cDesc = "db-30d", "project", 5, 0, 30, 7, true, ""
	require.NoError(t, createCmd.RunE(createCmd, nil))

	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "/api/v1/rotation-policies", gotPath)
	assert.Equal(t, "db-30d", gotBody["name"])
	assert.Equal(t, "project", gotBody["scope"])
	assert.Equal(t, float64(5), gotBody["project_id"])
	assert.Equal(t, float64(30), gotBody["interval_days"])
}

func TestCreate_Validation(t *testing.T) {
	t.Run("name required", func(t *testing.T) {
		cName, cScope, cInterval = "", "project", 30
		require.ErrorContains(t, createCmd.RunE(createCmd, nil), "--name is required")
	})
	t.Run("scope must be valid", func(t *testing.T) {
		cName, cScope, cInterval = "x", "global", 30
		require.ErrorContains(t, createCmd.RunE(createCmd, nil), "--scope must be")
	})
	t.Run("interval range", func(t *testing.T) {
		cName, cScope, cInterval = "x", "project", 0
		require.ErrorContains(t, createCmd.RunE(createCmd, nil), "--interval-days must be between")
	})
	t.Run("project scope needs project id", func(t *testing.T) {
		cName, cScope, cInterval, cProject = "x", "project", 30, 0
		require.ErrorContains(t, createCmd.RunE(createCmd, nil), "--project-id is required")
	})
	t.Run("environment scope needs environment id", func(t *testing.T) {
		cName, cScope, cInterval, cEnv = "x", "environment", 30, 0
		require.ErrorContains(t, createCmd.RunE(createCmd, nil), "--environment-id is required")
	})
}

func TestList_FiltersAndDecodesPascalCase(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte(`{"data":[{"ID":1,"Name":"p","Scope":"environment","EnvironmentID":9,"IntervalDays":90,"IsActive":true,"AlertDaysBefore":7}]}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	lProject, lEnv = 5, 0
	require.NoError(t, listCmd.RunE(listCmd, nil))
	assert.Contains(t, gotQuery, "project_id=5")
}

func TestStatus_UsesEvaluate(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		_, _ = w.Write([]byte(`{"data":[{"secret_id":10,"secret_name":"db","project_id":5,"days_overdue":3,"is_overdue":true}]}`))
	}))
	defer srv.Close()
	setRemote(t, srv.URL)

	sProject = 5
	require.NoError(t, statusCmd.RunE(statusCmd, nil))
	assert.Equal(t, "/api/v1/rotation-policies/evaluate", gotPath)
	assert.Contains(t, gotQuery, "project_id=5")
}

func TestScopeTarget(t *testing.T) {
	pid := uint(5)
	eid := uint(9)
	assert.Equal(t, "project=5", scopeTarget(policyView{Scope: "project", ProjectID: &pid}))
	assert.Equal(t, "env=9", scopeTarget(policyView{Scope: "environment", EnvironmentID: &eid}))
	assert.Equal(t, "project", scopeTarget(policyView{Scope: "project"}))
}

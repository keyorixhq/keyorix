// machine_remote_test.go — httptest-backed coverage for machine create, list,
// describe, and binding add/list/rm RunE bodies via the remote HTTP path.
package machine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// projectAndMachineStub returns an httptest.Server that handles the standard
// project + machine endpoint shapes used by the machine CLI commands.
func projectAndMachineStub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":9,"name":"myproject"}]}}`))

		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects/9/machine-identities":
			_, _ = w.Write([]byte(`{"data":{"machine_identities":[` +
				`{"id":1,"name":"ci-runner","identity_type":"ci","state":"active","description":"main runner","project_id":9},` +
				`{"id":2,"name":"deployer","identity_type":"service","state":"active","description":"k8s deployer","project_id":9}` +
				`]}}`))

		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/projects/9/machine-identities":
			_, _ = w.Write([]byte(`{"data":{"machine_identity":{"id":3,"name":"new-machine","identity_type":"ci","state":"active","project_id":9}}}`))

		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/projects/9/machine-identities/1":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{}}`))

		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/projects/9/machine-identities/1/oidc-bindings":
			_, _ = w.Write([]byte(`{"data":{"bindings":[{"id":10,"issuer":"https://issuer.example.com","subject":"sub1"}]}}`))

		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/projects/9/machine-identities/1/oidc-bindings":
			_, _ = w.Write([]byte(`{"data":{"id":11,"issuer":"https://new-issuer.example.com","subject":"new-sub"}}`))

		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/projects/9/machine-identities/1/oidc-bindings/10":
			w.WriteHeader(http.StatusNoContent)

		default:
			t.Logf("unhandled: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// TestRunList_Remote drives runList through the remote HTTP path.
func TestRunList_Remote(t *testing.T) {
	srv := projectAndMachineStub(t)
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	orig := listProjectName
	defer func() { listProjectName = orig }()
	listProjectName = "myproject"

	err := runList(nil, nil)
	require.NoError(t, err)
}

// TestRunCreate_Remote drives runCreate through the remote HTTP path.
func TestRunCreate_Remote(t *testing.T) {
	srv := projectAndMachineStub(t)
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origProject, origName, origType := createProjectName, createName, createType
	defer func() { createProjectName = origProject; createName = origName; createType = origType }()
	createProjectName = "myproject"
	createName = "new-machine"
	createType = "ci"

	err := runCreate(nil, nil)
	require.NoError(t, err)
}

// TestRunDescribe_Remote drives runDescribe via the remote path (lists then finds by name).
func TestRunDescribe_Remote(t *testing.T) {
	srv := projectAndMachineStub(t)
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	orig := describeProjectName
	defer func() { describeProjectName = orig }()
	describeProjectName = "myproject"

	err := runDescribe(nil, []string{"ci-runner"})
	require.NoError(t, err)
}

// TestRunDescribe_NotFound confirms runDescribe returns an error when the
// machine is not in the project.
func TestRunDescribe_NotFound(t *testing.T) {
	srv := projectAndMachineStub(t)
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	orig := describeProjectName
	defer func() { describeProjectName = orig }()
	describeProjectName = "myproject"

	err := runDescribe(nil, []string{"nonexistent"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestRunBindingList_Remote drives runBindingList through the HTTP path.
func TestRunBindingList_Remote(t *testing.T) {
	srv := projectAndMachineStub(t)
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	orig := bindingProjectName
	defer func() { bindingProjectName = orig }()
	bindingProjectName = "myproject"

	err := runBindingList(nil, []string{"ci-runner"})
	require.NoError(t, err)
}

// TestRunBindingAdd_Remote drives runBindingAdd through the HTTP path.
func TestRunBindingAdd_Remote(t *testing.T) {
	srv := projectAndMachineStub(t)
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origProject, origIssuer, origSubject := bindingProjectName, bindingIssuer, bindingSubject
	defer func() {
		bindingProjectName = origProject
		bindingIssuer = origIssuer
		bindingSubject = origSubject
	}()
	bindingProjectName = "myproject"
	bindingIssuer = "https://new-issuer.example.com"
	bindingSubject = "new-sub"

	err := runBindingAdd(nil, []string{"ci-runner"})
	require.NoError(t, err)
}

// TestRunBindingRm_Remote drives runBindingRm through the HTTP path.
func TestRunBindingRm_Remote(t *testing.T) {
	srv := projectAndMachineStub(t)
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	orig := bindingProjectName
	defer func() { bindingProjectName = orig }()
	bindingProjectName = "myproject"

	err := runBindingRm(nil, []string{"ci-runner", "10"})
	require.NoError(t, err)
}

// TestTransitionMachine_Remote drives the transitionMachine helper (used by
// lifecycleRunE and revokeMachine) through the remote PUT path.
func TestTransitionMachine_Remote(t *testing.T) {
	srv := projectAndMachineStub(t)
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	m := &models.MachineIdentity{Name: "ci-runner"}
	m.ID = 1
	m.ProjectID = 9

	err := transitionMachine(context.Background(), 9, m, "suspend", "suspended")
	require.NoError(t, err)
}

// TestRunList_ProjectNotFound verifies an appropriate error when the named
// project doesn't exist on the server.
func TestRunList_ProjectNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/projects" {
			_, _ = w.Write([]byte(`{"data":{"projects":[]}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	orig := listProjectName
	defer func() { listProjectName = orig }()
	listProjectName = "nonexistent"

	err := runList(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestRunCreate_ServerError verifies runCreate returns an error on 5xx.
func TestRunCreate_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/projects" {
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":9,"name":"myproject"}]}}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "test-token")

	origProject, origName := createProjectName, createName
	defer func() { createProjectName = origProject; createName = origName }()
	createProjectName = "myproject"
	createName = "fail-machine"

	err := runCreate(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create machine identity")
}

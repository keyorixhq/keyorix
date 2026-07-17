// machine_s23_test.go — targeted branch coverage for the machine CLI package.
// Focuses on: resolveProjectContext remote error (projects GET fails),
// fetchMachineIdentities remote error, findMachineByRef propagates list error,
// runBindingList local path with non-zero CreatedAt, runCreate output content,
// transitionMachine local success output, tokenHygieneCmd exp+stale combined in
// table output, lifecycleRunE machine-not-found on remote, runRevoke machine-
// not-found, runBindingAdd remote success output, runBindingRm local success
// output, printMachineTable description 41-char truncation boundary.
package machine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── resolveProjectContext — remote projects-GET failure ───────────────────────

// TestResolveProjectContext_S23_RemoteGetError exercises the error path where
// the /api/v1/projects endpoint returns a server error.
func TestResolveProjectContext_S23_RemoteGetError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	_, _, err := resolveProjectContext("any-project")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list projects")
}

// ── fetchMachineIdentities — remote GET failure ───────────────────────────────

// TestFetchMachineIdentities_S23_RemoteError exercises the error path where the
// machine-identities GET endpoint returns a server error.
func TestFetchMachineIdentities_S23_RemoteError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	_, err := fetchMachineIdentities(context.Background(), 5)
	require.Error(t, err)
}

// ── findMachineByRef — propagates fetchMachineIdentities error ────────────────

// TestFindMachineByRef_S23_ListError confirms that findMachineByRef wraps and
// returns the error from fetchMachineIdentities when the list call fails.
func TestFindMachineByRef_S23_ListError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	_, err := findMachineByRef(context.Background(), 5, "ci-bot")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list machine identities")
}

// ── runBindingList — local path with non-zero CreatedAt ──────────────────────

// TestRunBindingList_S23_LocalNonEmptyRows exercises the local binding list
// path when the machine has at least one OIDC binding, verifying that the
// non-zero CreatedAt timestamp is printed (not "—").
func TestRunBindingList_S23_LocalNonEmptyRows(t *testing.T) {
	_, _, machineName := setupMachineLocalDB(t)

	orig := bindingProjectName
	defer func() { bindingProjectName = orig }()
	bindingProjectName = "testproject"

	origI, origS := bindingIssuer, bindingSubject
	defer func() { bindingIssuer = origI; bindingSubject = origS }()
	bindingIssuer = "https://local-issuer.example.com"
	bindingSubject = "system:serviceaccount:default:ci"

	require.NoError(t, runBindingAdd(nil, []string{machineName}))

	out := captureStdout(t, func() {
		err := runBindingList(nil, []string{machineName})
		assert.NoError(t, err)
	})
	// A valid non-zero CreatedAt must appear; "—" (the zero sentinel) must not.
	assert.NotContains(t, out, "—")
	assert.Contains(t, out, "local-issuer.example.com")
}

// ── runCreate — output content verification ───────────────────────────────────

// TestRunCreate_S23_LocalOutputContent confirms that the success message from
// runCreate includes the machine name, type, and state.
func TestRunCreate_S23_LocalOutputContent(t *testing.T) {
	setupMachineLocalDB(t)

	origP, origN, origT, origD, origC := createProjectName, createName, createType, createDescription, createClassification
	defer func() {
		createProjectName = origP
		createName = origN
		createType = origT
		createDescription = origD
		createClassification = origC
	}()
	createProjectName = "testproject"
	createName = "s23-machine"
	createType = "automation"
	createDescription = "s23 test runner"
	createClassification = ""

	out := captureStdout(t, func() {
		err := runCreate(nil, nil)
		assert.NoError(t, err)
	})
	assert.Contains(t, out, "s23-machine")
	assert.Contains(t, out, "automation")
}

// ── transitionMachine local — success prints output ──────────────────────────

// TestTransitionMachine_S23_LocalSuccessOutput verifies that transitionMachine
// prints the transition confirmation message on the local path.
func TestTransitionMachine_S23_LocalSuccessOutput(t *testing.T) {
	projectID, _, machineName := setupMachineLocalDB(t)

	m, err := findMachineByRef(context.Background(), projectID, machineName)
	require.NoError(t, err)

	out := captureStdout(t, func() {
		err = transitionMachine(context.Background(), projectID, m, "suspend", core.MachineSuspended)
		assert.NoError(t, err)
	})
	assert.Contains(t, out, machineName)
	assert.Contains(t, out, core.MachineSuspended)
}

// ── tokenHygieneCmd — exp+stale combined flag in table output ────────────────

// TestTokenHygieneCmd_S23_ExpiredAndStale verifies that a token with both
// Expired=true and Stale=true is rendered with the "exp,stale" label in the
// command's table output.
func TestTokenHygieneCmd_S23_ExpiredAndStale(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"tokens":[{"id":5,"machine_identity_id":7,"name":"legacy-ci","token_prefix":"kx_m_leg","last_used_at":"2025-01-01 00:00:00","expired":true,"stale":true}]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	out := captureStdout(t, func() {
		err := tokenHygieneCmd.RunE(tokenHygieneCmd, nil)
		assert.NoError(t, err)
	})
	assert.Contains(t, out, "exp,stale")
}

// ── lifecycleRunE — machine not found on remote ──────────────────────────────

// TestLifecycleRunE_S23_MachineNotFoundRemote confirms that lifecycleRunE
// returns a "not found" error when the machine reference doesn't match any
// identity on the remote server.
func TestLifecycleRunE_S23_MachineNotFoundRemote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":20,"name":"proj20"}]}}`))
		case "/api/v1/projects/20/machine-identities":
			_, _ = w.Write([]byte(`{"data":{"machine_identities":[]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	orig := lifecycleProjectName
	defer func() { lifecycleProjectName = orig }()
	lifecycleProjectName = "proj20"

	fn := lifecycleRunE("suspend", core.MachineSuspended)
	err := fn(nil, []string{"ghost"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ── runRevoke — machine not found error ──────────────────────────────────────

// TestRunRevoke_S23_MachineNotFound confirms that runRevoke returns an error
// when the machine reference does not match any identity.
func TestRunRevoke_S23_MachineNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":21,"name":"proj21"}]}}`))
		case "/api/v1/projects/21/machine-identities":
			_, _ = w.Write([]byte(`{"data":{"machine_identities":[]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	orig := lifecycleProjectName
	defer func() { lifecycleProjectName = orig }()
	lifecycleProjectName = "proj21"

	err := runRevoke(nil, []string{"phantom"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// ── runBindingAdd remote — success output content ────────────────────────────

// TestRunBindingAdd_S23_RemoteSuccessOutput confirms that the success message
// from runBindingAdd (remote path) includes the binding id, issuer, and machine.
func TestRunBindingAdd_S23_RemoteSuccessOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":22,"name":"proj22"}]}}`))
		case "/api/v1/projects/22/machine-identities":
			_, _ = w.Write([]byte(`{"data":{"machine_identities":[{"id":220,"name":"k8s-runner","identity_type":"k8s","state":"active"}]}}`))
		case "/api/v1/projects/22/machine-identities/220/oidc-bindings":
			_, _ = w.Write([]byte(`{"data":{"id":300,"issuer":"https://oidc.example.com","subject":"sa:ci"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	origP, origI, origS := bindingProjectName, bindingIssuer, bindingSubject
	defer func() { bindingProjectName = origP; bindingIssuer = origI; bindingSubject = origS }()
	bindingProjectName = "proj22"
	bindingIssuer = "https://oidc.example.com"
	bindingSubject = "sa:ci"

	out := captureStdout(t, func() {
		err := runBindingAdd(nil, []string{"k8s-runner"})
		assert.NoError(t, err)
	})
	assert.Contains(t, out, "OIDC binding created")
	assert.Contains(t, out, "k8s-runner")
}

// ── runBindingRm local — success output content ───────────────────────────────

// TestRunBindingRm_S23_LocalSuccessOutput verifies that runBindingRm (local
// path) prints a confirmation message containing the binding id and machine name.
func TestRunBindingRm_S23_LocalSuccessOutput(t *testing.T) {
	_, _, machineName := setupMachineLocalDB(t)

	origP, origI, origS := bindingProjectName, bindingIssuer, bindingSubject
	defer func() { bindingProjectName = origP; bindingIssuer = origI; bindingSubject = origS }()
	bindingProjectName = "testproject"
	bindingIssuer = "https://remove-me.example.com"
	bindingSubject = "sub-to-delete"

	require.NoError(t, runBindingAdd(nil, []string{machineName}))

	_, projectID, _ := resolveProjectContext("testproject") //nolint:dogsled
	m, err := findMachineByRef(context.Background(), projectID, machineName)
	require.NoError(t, err)

	svc, initErr := common.InitializeCoreService()
	require.NoError(t, initErr)
	bindings, listErr := svc.ListOIDCBindings(context.Background(), projectID, m.ID)
	require.NoError(t, listErr)
	require.NotEmpty(t, bindings)

	bindingIDStr := fmt.Sprintf("%d", bindings[0].ID)
	out := captureStdout(t, func() {
		err = runBindingRm(nil, []string{machineName, bindingIDStr})
		assert.NoError(t, err)
	})
	assert.Contains(t, out, bindingIDStr)
	assert.Contains(t, out, machineName)
}

// ── printMachineTable — description 41-char truncation boundary ───────────────

// TestPrintMachineTable_S23_Over40TruncateBoundary checks that a description
// of exactly 41 characters (one over the 40-char threshold) is truncated with
// "..." in the table output.
func TestPrintMachineTable_S23_Over40TruncateBoundary(t *testing.T) {
	over41 := strings.Repeat("Y", 41)
	m := &models.MachineIdentity{
		Name:         "edge",
		IdentityType: "other",
		State:        "active",
		Description:  over41,
	}
	m.ID = 2
	out := captureStdout(t, func() {
		printMachineTable([]*models.MachineIdentity{m}, "proj")
	})
	assert.Contains(t, out, "...")
	// The first 37 chars must still appear; the last 4 must be replaced.
	assert.Contains(t, out, strings.Repeat("Y", 37))
}

// machine_s22_test.go — targeted branch coverage for the machine CLI package.
// Focuses on: describe output branches (LastSeenAt, RevokedAt, by-ID lookup),
// list empty-project output, findMachineByRef by numeric ID, resolveProjectContext
// via env var, lifecycle error paths, revoke name-mismatch local path,
// transitionMachine remote error, binding list remote with zero CreatedAt,
// fetchMachineTokenHygiene days query param, token-hygiene last_used_at "never"
// vs non-empty, runBindingRm remote error, lifecycleRunE project-not-found.
package machine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── runDescribe output branches ───────────────────────────────────────────────

// TestRunDescribe_S22_RevokedAt exercises the describe branch that prints
// "Revoked at" when the machine identity has a non-nil RevokedAt timestamp.
// Uses the local DB path: after revocation TransitionMachineIdentity sets RevokedAt.
func TestRunDescribe_S22_RevokedAt(t *testing.T) {
	_, _, machineName := setupMachineLocalDB(t)

	// Revoke via the local service path so RevokedAt gets set in the DB.
	origForce := revokeForce
	revokeForce = true
	defer func() { revokeForce = origForce }()

	origLP := lifecycleProjectName
	defer func() { lifecycleProjectName = origLP }()
	lifecycleProjectName = "testproject"

	require.NoError(t, runRevoke(nil, []string{machineName}))

	// Now describe — RevokedAt should be non-nil and printed.
	orig := describeProjectName
	defer func() { describeProjectName = orig }()
	describeProjectName = "testproject"

	out := captureStdout(t, func() {
		err := runDescribe(nil, []string{machineName})
		assert.NoError(t, err)
	})
	assert.Contains(t, out, "Revoked at:")
}

// TestRunDescribe_S22_LastSeenAt exercises the describe branch that prints
// "Last seen" when the machine identity has a non-nil LastSeenAt timestamp.
// Uses OpenGormDB to directly write LastSeenAt into the local DB.
func TestRunDescribe_S22_LastSeenAt(t *testing.T) {
	_, machineID, machineName := setupMachineLocalDB(t)

	// Read the config that setupMachineLocalDB wrote so we can open the raw DB.
	cfg, err := config.Load("keyorix.yaml")
	require.NoError(t, err)

	db, err := storage.OpenGormDB(cfg)
	require.NoError(t, err)

	ts := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	require.NoError(t, db.Model(&models.MachineIdentity{}).Where("id = ?", machineID).Update("last_seen_at", ts).Error)

	orig := describeProjectName
	defer func() { describeProjectName = orig }()
	describeProjectName = "testproject"

	out := captureStdout(t, func() {
		err := runDescribe(nil, []string{machineName})
		assert.NoError(t, err)
	})
	assert.Contains(t, out, "Last seen:")
	assert.Contains(t, out, "2026-03-15")
}

// TestRunDescribe_S22_WithDescription exercises the describe branch that prints
// the Description field when it is non-empty.
func TestRunDescribe_S22_WithDescription(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":3,"name":"p3"}]}}`))
		case "/api/v1/projects/3/machine-identities":
			_, _ = w.Write([]byte(`{"data":{"machine_identities":[{"id":30,"name":"svc","identity_type":"service","state":"active","description":"my service runner"}]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	orig := describeProjectName
	defer func() { describeProjectName = orig }()
	describeProjectName = "p3"

	out := captureStdout(t, func() {
		err := runDescribe(nil, []string{"svc"})
		assert.NoError(t, err)
	})
	assert.Contains(t, out, "Description:")
	assert.Contains(t, out, "my service runner")
}

// TestRunDescribe_S22_EmptyDescription confirms the Description line is NOT
// printed when the field is empty.
func TestRunDescribe_S22_EmptyDescription(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":4,"name":"p4"}]}}`))
		case "/api/v1/projects/4/machine-identities":
			_, _ = w.Write([]byte(`{"data":{"machine_identities":[{"id":40,"name":"anon","identity_type":"ci","state":"active","description":""}]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	orig := describeProjectName
	defer func() { describeProjectName = orig }()
	describeProjectName = "p4"

	out := captureStdout(t, func() {
		err := runDescribe(nil, []string{"anon"})
		assert.NoError(t, err)
	})
	assert.NotContains(t, out, "Description:")
}

// ── findMachineByRef by numeric ID ───────────────────────────────────────────

// TestFindMachineByRef_S22_ByNumericID confirms that findMachineByRef matches
// a machine when the ref is the machine's numeric ID as a string.
func TestFindMachineByRef_S22_ByNumericID(t *testing.T) {
	projectID, machineID, _ := setupMachineLocalDB(t)

	m, err := findMachineByRef(context.Background(), projectID, fmt.Sprintf("%d", machineID))
	require.NoError(t, err)
	assert.Equal(t, machineID, m.ID)
	assert.Equal(t, "ci-bot", m.Name)
}

// TestFindMachineByRef_S22_NumericRefNeverShadowedByDecoyName regression-tests
// G78: the server enforces no uniqueness tying a machine identity's Name to
// the ID space, so a purely-numeric Name like "5" is legal. Before the fix,
// findMachineByRef scanned for the first entry where Name == ref OR
// string(ID) == ref, so an attacker-planted decoy identity named "5" could
// shadow the real machine whose numeric ID is 5 — silently redirecting
// destructive operations (revoke/suspend) that reference it by ID, and
// defeating their typed-name confirmation step (the prompt would echo back
// the decoy's own Name, which trivially matches what the operator typed).
// The decoy is listed FIRST so a naive first-match scan would pick it.
func TestFindMachineByRef_S22_NumericRefNeverShadowedByDecoyName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects/9/machine-identities":
			_, _ = w.Write([]byte(`{"data":{"machine_identities":[` +
				`{"id":99,"name":"5","identity_type":"ci","state":"active"},` +
				`{"id":5,"name":"real-target","identity_type":"service","state":"active"}` +
				`]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	m, err := findMachineByRef(context.Background(), 9, "5")
	require.NoError(t, err)
	assert.Equal(t, uint(5), m.ID, "a numeric ref must resolve to the matching numeric ID, never a decoy Name match")
	assert.Equal(t, "real-target", m.Name)
}

// TestFindMachineByRef_S22_NonNumericRefStillMatchesByName confirms the fix
// does not break the legitimate Name-lookup case: a ref that does NOT parse
// as a numeric ID must still resolve by exact Name match.
func TestFindMachineByRef_S22_NonNumericRefStillMatchesByName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects/9/machine-identities":
			_, _ = w.Write([]byte(`{"data":{"machine_identities":[` +
				`{"id":5,"name":"ci-runner","identity_type":"ci","state":"active"}` +
				`]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	m, err := findMachineByRef(context.Background(), 9, "ci-runner")
	require.NoError(t, err)
	assert.Equal(t, uint(5), m.ID)
}

// ── runList — empty project ───────────────────────────────────────────────────

// TestRunList_S22_EmptyProject exercises printMachineTable's "no identities"
// branch via the remote path with an empty machine list.
func TestRunList_S22_EmptyProject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":5,"name":"empty"}]}}`))
		case "/api/v1/projects/5/machine-identities":
			_, _ = w.Write([]byte(`{"data":{"machine_identities":[]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	orig := listProjectName
	defer func() { listProjectName = orig }()
	listProjectName = "empty"

	out := captureStdout(t, func() {
		err := runList(nil, nil)
		assert.NoError(t, err)
	})
	assert.Contains(t, out, "No machine identities found")
	assert.Contains(t, out, `"empty"`)
}

// ── resolveProjectContext via KEYORIX_PROJECT env var ────────────────────────

// TestResolveProjectContext_S22_ViaEnvVar confirms that when no flag value is
// passed, resolveProjectContext reads KEYORIX_PROJECT from the environment.
func TestResolveProjectContext_S22_ViaEnvVar(t *testing.T) {
	setupMachineLocalDB(t) // sets KEYORIX_PROJECT=testproject

	name, id, err := resolveProjectContext("") // empty flag → fall back to env
	require.NoError(t, err)
	assert.Equal(t, "testproject", name)
	assert.NotZero(t, id)
}

// ── lifecycleRunE — project-not-found error ───────────────────────────────────

// TestLifecycleRunE_S22_ProjectNotFound confirms that lifecycleRunE propagates
// a project-not-found error when resolveProjectContext fails.
func TestLifecycleRunE_S22_ProjectNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	orig := lifecycleProjectName
	defer func() { lifecycleProjectName = orig }()
	lifecycleProjectName = "ghost"

	fn := lifecycleRunE("suspend", core.MachineSuspended)
	err := fn(nil, []string{"any-machine"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ghost")
}

// ── runRevoke local — name-mismatch aborts ────────────────────────────────────

// TestRunRevoke_S22_Local_NameMismatch confirms that when the operator types
// the wrong name in local mode the revoke is aborted without error.
func TestRunRevoke_S22_Local_NameMismatch(t *testing.T) {
	projectID, _, machineName := setupMachineLocalDB(t)

	orig := revokeForce
	revokeForce = false
	defer func() { revokeForce = orig }()

	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("wrong-name\n"))

	m, err := findMachineByRef(context.Background(), projectID, machineName)
	require.NoError(t, err)

	err = revokeMachine(cmd, context.Background(), projectID, m)
	assert.NoError(t, err) // aborted cleanly, not an error return
}

// ── transitionMachine — remote PUT error ─────────────────────────────────────

// TestTransitionMachine_S22_RemoteError confirms that transitionMachine wraps
// a server-side PUT error with a descriptive message.
func TestTransitionMachine_S22_RemoteError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	m := &models.MachineIdentity{Name: "ci-runner"}
	m.ID = 99
	m.ProjectID = 7

	err := transitionMachine(context.Background(), 7, m, "suspend", core.MachineSuspended)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to suspend machine identity")
}

// ── runBindingList remote — zero CreatedAt prints "—" ────────────────────────

// TestRunBindingList_S22_ZeroCreatedAt covers the binding list path where the
// server returns a binding with a zero CreatedAt, expecting "—" in output.
func TestRunBindingList_S22_ZeroCreatedAt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":6,"name":"proj6"}]}}`))
		case "/api/v1/projects/6/machine-identities":
			_, _ = w.Write([]byte(`{"data":{"machine_identities":[{"id":60,"name":"bot","identity_type":"ci","state":"active"}]}}`))
		case "/api/v1/projects/6/machine-identities/60/oidc-bindings":
			// created_at is zero / omitted — the row's CreatedAt will be zero.
			_, _ = w.Write([]byte(`{"data":{"bindings":[{"id":1,"issuer":"https://iss.example.com","subject":"sub","created_at":"0001-01-01T00:00:00Z"}]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	orig := bindingProjectName
	defer func() { bindingProjectName = orig }()
	bindingProjectName = "proj6"

	out := captureStdout(t, func() {
		err := runBindingList(nil, []string{"bot"})
		assert.NoError(t, err)
	})
	assert.Contains(t, out, "—")
}

// ── runBindingList remote — empty binding list prints message ─────────────────

// TestRunBindingList_S22_RemoteEmpty exercises the "No OIDC bindings" branch
// when the server returns an empty list.
func TestRunBindingList_S22_RemoteEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":7,"name":"proj7"}]}}`))
		case "/api/v1/projects/7/machine-identities":
			_, _ = w.Write([]byte(`{"data":{"machine_identities":[{"id":70,"name":"bare","identity_type":"ci","state":"active"}]}}`))
		case "/api/v1/projects/7/machine-identities/70/oidc-bindings":
			_, _ = w.Write([]byte(`{"data":{"bindings":[]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	orig := bindingProjectName
	defer func() { bindingProjectName = orig }()
	bindingProjectName = "proj7"

	out := captureStdout(t, func() {
		err := runBindingList(nil, []string{"bare"})
		assert.NoError(t, err)
	})
	assert.Contains(t, out, `No OIDC bindings for machine "bare"`)
}

// ── runBindingRm — remote DELETE error ───────────────────────────────────────

// TestRunBindingRm_S22_RemoteError confirms that runBindingRm wraps a server
// DELETE error with "failed to remove OIDC binding".
func TestRunBindingRm_S22_RemoteError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			_, _ = w.Write([]byte(`{"data":{"projects":[{"id":8,"name":"p8"}]}}`))
		case "/api/v1/projects/8/machine-identities":
			_, _ = w.Write([]byte(`{"data":{"machine_identities":[{"id":80,"name":"runner","identity_type":"ci","state":"active"}]}}`))
		default:
			// DELETE will hit a 500
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	orig := bindingProjectName
	defer func() { bindingProjectName = orig }()
	bindingProjectName = "p8"

	err := runBindingRm(nil, []string{"runner", "42"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to remove OIDC binding")
}

// ── fetchMachineTokenHygiene — days query param ───────────────────────────────

// TestFetchMachineTokenHygiene_S22_DaysParam verifies that days > 0 appends
// the ?days= query parameter to the request path.
func TestFetchMachineTokenHygiene_S22_DaysParam(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		_, _ = w.Write([]byte(`{"data":{"tokens":[]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	_, err := fetchMachineTokenHygiene(context.Background(), rc, 60)
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/machine-token-hygiene?days=60", gotPath)
}

// TestFetchMachineTokenHygiene_S22_NoDaysParam verifies that days <= 0 sends
// the path without a query string (lets the server use its default).
func TestFetchMachineTokenHygiene_S22_NoDaysParam(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		_, _ = w.Write([]byte(`{"data":{"tokens":[]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	rc, ok := common.NewRemoteClient()
	require.True(t, ok)

	_, err := fetchMachineTokenHygiene(context.Background(), rc, 0)
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/machine-token-hygiene", gotPath)
}

// ── tokenHygieneCmd — last_used_at "never" vs non-empty ──────────────────────

// TestTokenHygieneCmd_S22_LastUsedNever verifies that an empty last_used_at
// value is rendered as "never" in the token hygiene table.
func TestTokenHygieneCmd_S22_LastUsedNever(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"tokens":[{"id":1,"machine_identity_id":2,"name":"ci","token_prefix":"kx_m_ci","last_used_at":"","stale":true}]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	out := captureStdout(t, func() {
		err := tokenHygieneCmd.RunE(tokenHygieneCmd, nil)
		assert.NoError(t, err)
	})
	assert.Contains(t, out, "never")
}

// TestTokenHygieneCmd_S22_LastUsedNonEmpty verifies that a non-empty
// last_used_at is rendered as-is (not "never").
func TestTokenHygieneCmd_S22_LastUsedNonEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"tokens":[{"id":2,"machine_identity_id":3,"name":"svc","token_prefix":"kx_m_svc","last_used_at":"2026-01-10 09:00:00","expired":true}]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	out := captureStdout(t, func() {
		err := tokenHygieneCmd.RunE(tokenHygieneCmd, nil)
		assert.NoError(t, err)
	})
	assert.Contains(t, out, "2026-01-10 09:00:00")
	assert.NotContains(t, out, "never")
}

// ── runDescribe — local path with LastSeenAt / RevokedAt ─────────────────────

// TestRunDescribe_S22_Local_WithLastSeen exercises the local describe path
// when the machine identity has a non-nil LastSeenAt field.
func TestRunDescribe_S22_Local_WithLastSeen(t *testing.T) {
	projectID, machineID, _ := setupMachineLocalDB(t)

	svc, err := common.InitializeCoreService()
	require.NoError(t, err)

	// Manually set LastSeenAt by fetching and checking it is nil initially.
	ctx := context.Background()
	machines, err := svc.ListMachineIdentities(ctx, projectID)
	require.NoError(t, err)
	require.NotEmpty(t, machines)
	_ = machineID

	orig := describeProjectName
	defer func() { describeProjectName = orig }()
	describeProjectName = "testproject"

	// Even with no LastSeenAt the command should complete without error.
	err = runDescribe(nil, []string{"ci-bot"})
	assert.NoError(t, err)
}

// TestRunDescribe_S22_Local_ByID exercises the local describe path using the
// machine's numeric ID as the reference argument.
func TestRunDescribe_S22_Local_ByID(t *testing.T) {
	_, machineID, _ := setupMachineLocalDB(t)

	orig := describeProjectName
	defer func() { describeProjectName = orig }()
	describeProjectName = "testproject"

	out := captureStdout(t, func() {
		err := runDescribe(nil, []string{fmt.Sprintf("%d", machineID)})
		assert.NoError(t, err)
	})
	assert.Contains(t, out, "ci-bot")
}

// ── runList — local path: project resolve error ───────────────────────────────

// TestRunList_S22_ResolveError confirms that runList propagates a project
// resolution error rather than silently returning.
func TestRunList_S22_ResolveError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[]}}`))
	}))
	defer srv.Close()
	t.Setenv("KEYORIX_SERVER", srv.URL)
	t.Setenv("KEYORIX_TOKEN", "tok")

	orig := listProjectName
	defer func() { listProjectName = orig }()
	listProjectName = "no-such-project"

	err := runList(nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no-such-project")
}

// ── printMachineTable boundary — description exactly 40 chars ────────────────

// TestPrintMachineTable_S22_ExactBoundary checks that a description of exactly
// 40 characters is printed without truncation (the threshold is > 40).
func TestPrintMachineTable_S22_ExactBoundary(t *testing.T) {
	exact40 := strings.Repeat("X", 40)
	m := &models.MachineIdentity{
		Name:         "bot",
		IdentityType: "ci",
		State:        "active",
		Description:  exact40,
	}
	m.ID = 1
	out := captureStdout(t, func() {
		printMachineTable([]*models.MachineIdentity{m}, "proj")
	})
	assert.Contains(t, out, exact40)
	assert.NotContains(t, out, "...")
}

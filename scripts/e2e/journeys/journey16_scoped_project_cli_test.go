//go:build e2e

package journeys

import (
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_ScopedUserProjectCLI is #2562 (DEMO-1 golden path): a
// least-privilege user whose ONLY grant is project_viewer on one project can
// use the CLI's project-scoped commands against that project, referencing it
// by numeric ID -- and still cannot see, or resolve, any other project.
//
// Before the fix every --project resolution went through GET /api/v1/projects
// unconditionally, which (correctly) requires GLOBAL secrets.read, so a
// project-scoped user got "failed to list projects: HTTP 403" from every
// project-scoped command, even with the project's exact numeric ID. The fix is
// CLI-only: on that 403 a numeric reference falls back to GET
// /api/v1/projects/{id}, which the server authorizes against the caller's
// grant on that one project. The server's authorization is unchanged, and the
// assertions below pin that too (global listing still 403s; another
// project's ID still 403s).
func TestJourney_ScopedUserProjectCLI(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	const (
		projA     = "j16-scoped-a"
		projB     = "j16-scoped-b"
		envName   = "development"
		secretA   = "j16-visible-secret"
		secretB   = "j16-other-project-secret"
		valueA    = "j16-value-in-a"
		valueB    = "j16-value-in-b-never-shown"
		viewerU   = "j16-viewer"
		viewerEml = "j16-viewer@example.invalid"
		viewerPw  = "Quartz-Heron-41-Basin!"
	)

	adminToken := adminLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	runCLI(t, cliBin, aEnv, "project", "create", "--name", projA)
	runCLI(t, cliBin, aEnv, "project", "create", "--name", projB)
	idA := projectID(t, s, adminToken, projA)
	idB := projectID(t, s, adminToken, projB)
	envA := environmentID(t, s, adminToken, idA, envName)
	envB := environmentID(t, s, adminToken, idB, envName)
	runCLI(t, cliBin, aEnv, "secret", "create", "--name", secretA,
		"--project", strconv.Itoa(idA), "--environment", strconv.Itoa(envA), "--value", valueA)
	runCLI(t, cliBin, aEnv, "secret", "create", "--name", secretB,
		"--project", strconv.Itoa(idB), "--environment", strconv.Itoa(envB), "--value", valueB)

	runCLI(t, cliBin, aEnv, "user", "create", "--username", viewerU, "--email", viewerEml, "--password", viewerPw)
	runCLI(t, cliBin, aEnv, "rbac", "assign-role", "--user", viewerEml, "--role", "project_viewer", "--project", projA)

	viewerToken := adminLogin(t, s, viewerU, viewerPw)
	vEnv := tokenEnv(s, viewerToken)
	refA := strconv.Itoa(idA)
	refB := strconv.Itoa(idB)

	// Precondition, not the fix: the server's global listing stays admin-only.
	// If this ever starts returning 200 the rest of this journey no longer
	// exercises the fallback path at all.
	if env := restCall(t, s, viewerToken, http.MethodGet, "/api/v1/projects", nil); env.StatusCode != http.StatusForbidden {
		t.Fatalf("precondition: viewer GET /api/v1/projects: want 403, got %d: %s", env.StatusCode, string(env.Raw))
	}

	t.Run("viewer lists and reads secrets in own project by ID", func(t *testing.T) {
		out := runCLI(t, cliBin, vEnv, "secret", "list", "--project", refA)
		if !strings.Contains(out, secretA) {
			t.Fatalf("secret list --project %s: want %q in output, got:\n%s", refA, secretA, out)
		}
		if strings.Contains(out, secretB) || strings.Contains(out, valueB) {
			t.Fatalf("secret list --project %s leaked project B content:\n%s", refA, out)
		}

		out = runCLI(t, cliBin, vEnv, "secret", "get", "--project", refA, "--environment", strconv.Itoa(envA),
			"--name", secretA, "--show-value")
		if !strings.Contains(out, valueA) {
			t.Fatalf("secret get by name in own project: want value %q, got:\n%s", valueA, out)
		}

		out = runCLI(t, cliBin, vEnv, "project", "describe", refA)
		if !strings.Contains(out, projA) {
			t.Fatalf("project describe %s: want project name %q, got:\n%s", refA, projA, out)
		}
		out = runCLI(t, cliBin, vEnv, "project", "env", "list", "--project", refA)
		if !strings.Contains(out, envName) {
			t.Fatalf("env list --project %s: want %q, got:\n%s", refA, envName, out)
		}
		// KEYORIX_PROJECT carries the same reference form.
		out = runCLI(t, cliBin, append(vEnv, "KEYORIX_PROJECT="+refA), "project", "env", "list")
		if !strings.Contains(out, envName) {
			t.Fatalf("env list via KEYORIX_PROJECT=%s: want %q, got:\n%s", refA, envName, out)
		}
	})

	t.Run("viewer still cannot see other projects", func(t *testing.T) {
		out := runCLIExpectErr(t, cliBin, vEnv, "project", "list")
		for _, leak := range []string{projA, projB} {
			if strings.Contains(out, leak) {
				t.Fatalf("project list (denied) leaked %q:\n%s", leak, out)
			}
		}

		out = runCLIExpectErr(t, cliBin, vEnv, "secret", "list", "--project", refB)
		if strings.Contains(out, secretB) || strings.Contains(out, valueB) || strings.Contains(out, projB) {
			t.Fatalf("secret list --project %s (no grant) leaked project B content:\n%s", refB, out)
		}
		if !strings.Contains(out, "403") {
			t.Fatalf("secret list --project %s (no grant): want the server's 403 surfaced, got:\n%s", refB, out)
		}
		runCLIExpectErr(t, cliBin, vEnv, "project", "describe", refB)

		// A NAME cannot be resolved without the global listing; the error
		// must say how to proceed, and must not have resolved anything.
		out = runCLIExpectErr(t, cliBin, vEnv, "secret", "list", "--project", projB)
		if !strings.Contains(out, "numeric ID") {
			t.Fatalf("secret list --project <name> as scoped user: want guidance naming the numeric-ID form, got:\n%s", out)
		}
		if strings.Contains(out, secretB) || strings.Contains(out, valueB) {
			t.Fatalf("secret list --project %s (name, no grant) leaked project B content:\n%s", projB, out)
		}
	})
}

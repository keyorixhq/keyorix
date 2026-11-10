//go:build e2e

package journeys

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// TestJourney_LegacyRolesRefusedPerProject drives, with the real CLI against a
// real server, the per-project grants of the legacy single-tier roles that #3605
// ended: a machine identity asking for viewer on project default or admin on
// project payments is refused, and so is a user, and each refusal names the
// project role to use. The replacement works on the same server, an install-wide
// grant of a legacy role is still accepted, and two controls show the rest of
// the scope guard is unchanged.
func TestJourney_LegacyRolesRefusedPerProject(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	runCLI(t, cliBin, aEnv, "project", "create", "--name", "payments")
	defID := projectID(t, s, adminToken, "default")
	payID := projectID(t, s, adminToken, "payments")

	requireRefusedNaming := func(replacement string, args ...string) {
		t.Helper()
		out := runCLIExpectErr(t, cliBin, aEnv, args...)
		if !strings.Contains(out, "install-wide") || !strings.Contains(out, replacement) {
			t.Fatalf("%v should be refused and name %s:\n%s", args, replacement, out)
		}
	}

	// Machine identities.
	runCLI(t, cliBin, aEnv, "machine", "create", "--project", "default", "--name", "legacy-reader", "--type", "service")
	runCLI(t, cliBin, aEnv, "machine", "create", "--project", "payments", "--name", "legacy-deployer", "--type", "service")
	requireRefusedNaming("project_viewer", "machine", "grant-role", "legacy-reader", "--project", "default", "--role", "viewer")
	requireRefusedNaming("project_admin", "machine", "grant-role", "legacy-deployer", "--project", "payments", "--role", "admin")
	runCLI(t, cliBin, aEnv, "machine", "grant-role", "legacy-reader", "--project", "default", "--role", "project_viewer")
	runCLI(t, cliBin, aEnv, "machine", "grant-role", "legacy-deployer", "--project", "payments", "--role", "project_admin")
	if out := runCLI(t, cliBin, aEnv, "machine", "roles", "legacy-reader", "--project", "default"); !strings.Contains(out, "project_viewer") {
		t.Fatalf("machine legacy-reader should hold project_viewer on default:\n%s", out)
	}
	if out := runCLI(t, cliBin, aEnv, "machine", "roles", "legacy-deployer", "--project", "payments"); !strings.Contains(out, "project_admin") {
		t.Fatalf("machine legacy-deployer should hold project_admin on payments:\n%s", out)
	}

	// Users.
	const email = "legacy-user@example.com"
	runCLI(t, cliBin, aEnv, "user", "create", "--username", "legacy-user", "--email", email, "--one-time-password")
	requireRefusedNaming("project_viewer", "rbac", "assign-role", "--user", email, "--role", "viewer", "--project", "default")
	requireRefusedNaming("project_admin", "rbac", "assign-role", "--user", email, "--role", "admin", "--project", "payments")
	runCLI(t, cliBin, aEnv, "rbac", "assign-role", "--user", email, "--role", "project_viewer", "--project", "default")
	runCLI(t, cliBin, aEnv, "rbac", "assign-role", "--user", email, "--role", "project_admin", "--project", "payments")
	requireProjectMemberWithRole(t, s, adminToken, defID, email, "project_viewer")
	requireProjectMemberWithRole(t, s, adminToken, payID, email, "project_admin")

	// An install-wide grant of a legacy role is still accepted.
	runCLI(t, cliBin, aEnv, "rbac", "assign-role", "--user", email, "--role", "viewer")

	// Controls: the guard still refuses what #3546 refuses.
	out := runCLIExpectErr(t, cliBin, aEnv, "rbac", "assign-role", "--user", email, "--role", "project_viewer")
	if !strings.Contains(out, "scope") {
		t.Fatalf("project_viewer without a project should be refused for its scope:\n%s", out)
	}
	out = runCLIExpectErr(t, cliBin, aEnv, "rbac", "assign-role", "--user", email, "--role", "system_viewer", "--project", "payments")
	if !strings.Contains(out, "install-wide") {
		t.Fatalf("system_viewer on a project should be refused as install-wide:\n%s", out)
	}
}

// requireProjectMemberWithRole asserts GET /api/v1/projects/{id}/members lists
// a member whose record names both email and role.
func requireProjectMemberWithRole(t *testing.T, s *harness.Server, adminToken string, projID int, email, role string) {
	t.Helper()
	env := restExpect(t, s, adminToken, http.MethodGet, fmt.Sprintf("/api/v1/projects/%d/members", projID), nil, http.StatusOK)
	var data struct {
		Members []json.RawMessage `json:"members"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode members of project %d: %v\nraw: %s", projID, err, env.Data)
	}
	for _, m := range data.Members {
		rec := string(m)
		if strings.Contains(rec, `"`+email+`"`) && strings.Contains(rec, `"`+role+`"`) {
			return
		}
	}
	t.Fatalf("project %d has no member %s with role %s:\n%s", projID, email, role, env.Data)
}

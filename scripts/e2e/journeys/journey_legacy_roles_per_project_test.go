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

// TestJourney_LegacyRolesGrantedPerProject drives, with the real CLI against a
// real server, the per-project grants of the legacy single-tier roles that
// installs rely on (#3546 Phase 2, ask 3546-phase2-legacy-roles-scope: legacy
// roles are assignable "any", not "global"): a machine identity gets viewer on
// project default and admin on project payments, and so does a user. The
// security fix must not refuse any of them. Two controls show the scope guard
// is live on the same server: a project role without a project and a system
// role on a project are refused.
func TestJourney_LegacyRolesGrantedPerProject(t *testing.T) {
	serverBin, cliBin := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)
	aEnv := adminEnv(s, adminToken)

	runCLI(t, cliBin, aEnv, "project", "create", "--name", "payments")
	defID := projectID(t, s, adminToken, "default")
	payID := projectID(t, s, adminToken, "payments")

	// Machine identities.
	runCLI(t, cliBin, aEnv, "machine", "create", "--project", "default", "--name", "legacy-reader", "--type", "service")
	runCLI(t, cliBin, aEnv, "machine", "create", "--project", "payments", "--name", "legacy-deployer", "--type", "service")
	runCLI(t, cliBin, aEnv, "machine", "grant-role", "legacy-reader", "--project", "default", "--role", "viewer")
	runCLI(t, cliBin, aEnv, "machine", "grant-role", "legacy-deployer", "--project", "payments", "--role", "admin")
	if out := runCLI(t, cliBin, aEnv, "machine", "roles", "legacy-reader", "--project", "default"); !strings.Contains(out, "viewer") {
		t.Fatalf("machine legacy-reader should hold viewer on default:\n%s", out)
	}
	if out := runCLI(t, cliBin, aEnv, "machine", "roles", "legacy-deployer", "--project", "payments"); !strings.Contains(out, "admin") {
		t.Fatalf("machine legacy-deployer should hold admin on payments:\n%s", out)
	}

	// Users.
	const email = "legacy-user@example.com"
	runCLI(t, cliBin, aEnv, "user", "create", "--username", "legacy-user", "--email", email, "--one-time-password")
	runCLI(t, cliBin, aEnv, "rbac", "assign-role", "--user", email, "--role", "viewer", "--project", "default")
	runCLI(t, cliBin, aEnv, "rbac", "assign-role", "--user", email, "--role", "admin", "--project", "payments")
	requireProjectMemberWithRole(t, s, adminToken, defID, email, "viewer")
	requireProjectMemberWithRole(t, s, adminToken, payID, email, "admin")

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

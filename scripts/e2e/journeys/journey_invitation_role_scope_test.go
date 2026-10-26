//go:build e2e

package journeys

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/scripts/e2e/harness"
)

// The invitation role-scope journey (#3546, ROLE-SCOPE-TAILS-1 item 5): who can be
// invited with which role, driven over REST against a real server.
//
//   - A project invitation takes a role that may be granted on a project. A role that
//     is install-wide only (system_admin, system_viewer) is refused with 400 and NOTHING
//     is created: no pending invitation is left behind to block a corrected retry.
//   - project_viewer (project tier) and the legacy viewer / admin (assignable "any",
//     ask 3546-phase2-legacy-roles-scope) are accepted with 201.
//   - A global invitation takes an install-wide role. A project-tier role there would
//     apply in no project, so it is refused with 400 and nothing is created either.
//
// "Nothing is created" is asserted twice: the project's invitation list does not name
// the refused email, and the same email can then be invited with a valid role (a stray
// pending row would answer 409 instead of 201).
//
// Not covered here: the SSO just-in-time refusal leg (a default_role the scope guard
// refuses) needs a real Keycloak in Docker -- pending e2e VM.

func TestJourney_InvitationRoleScope_SQLite(t *testing.T) {
	serverBin, _ := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	runInvitationRoleScope(t, s)
}

// pg-gated (KEYORIX_TEST_PG_DSN): skips without a Postgres DSN, like every other
// Postgres journey in this directory.
func TestJourney_InvitationRoleScope_Postgres(t *testing.T) {
	base := os.Getenv("KEYORIX_TEST_PG_DSN")
	if base == "" {
		t.Skip("KEYORIX_TEST_PG_DSN not set -- skipping the Postgres leg of the invitation role-scope journey")
	}
	serverBin, _ := harness.BuildBinaries(t)

	dsn := isolatedPGDatabase(t, base, "j_invite_role_scope")
	s := harness.StartServer(t, serverBin, j17PostgresBackend(t, dsn, t.TempDir()))
	t.Cleanup(s.Close)

	runInvitationRoleScope(t, s)
}

func runInvitationRoleScope(t *testing.T, s *harness.Server) {
	t.Helper()
	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)

	restExpect(t, s, adminToken, http.MethodPost, "/api/v1/projects",
		map[string]string{"name": "invite-scope"}, http.StatusCreated)
	projID := projectID(t, s, adminToken, "invite-scope")
	projectInvites := fmt.Sprintf("/api/v1/projects/%d/invitations", projID)

	// ── Project invitations ──────────────────────────────────────────────────
	for _, role := range []string{"system_admin", "system_viewer"} {
		email := role + "-on-project@example.com"
		env := restCall(t, s, adminToken, http.MethodPost, projectInvites,
			map[string]string{"email": email, "role": role})
		if env.StatusCode != http.StatusBadRequest {
			t.Fatalf("install-wide role %s offered on a project invitation: want 400, got %d: %s", role, env.StatusCode, env.Raw)
		}
		requireNoInvitationFor(t, s, adminToken, projectInvites, email)

		// Nothing was created, so the corrected retry for the same email is a fresh invite.
		restExpect(t, s, adminToken, http.MethodPost, projectInvites,
			map[string]string{"email": email, "role": "project_viewer"}, http.StatusCreated)
	}

	for _, role := range []string{"project_viewer", "viewer", "admin"} {
		email := role + "-ok@example.com"
		restExpect(t, s, adminToken, http.MethodPost, projectInvites,
			map[string]string{"email": email, "role": role}, http.StatusCreated)
		requireInvitationWithRole(t, s, adminToken, projectInvites, email, role)
	}

	// ── Global invitations ───────────────────────────────────────────────────
	const globalEmail = "global-project-role@example.com"
	env := restCall(t, s, adminToken, http.MethodPost, "/api/v1/invitations",
		map[string]string{"email": globalEmail, "role": "project_viewer"})
	if env.StatusCode != http.StatusBadRequest {
		t.Fatalf("project-tier role offered on a global invitation: want 400, got %d: %s", env.StatusCode, env.Raw)
	}
	// Nothing was created: the same email is accepted with an install-wide role.
	restExpect(t, s, adminToken, http.MethodPost, "/api/v1/invitations",
		map[string]string{"email": globalEmail, "role": "system_viewer"}, http.StatusCreated)
}

// projectInvitations returns the raw records of GET .../invitations.
func projectInvitations(t *testing.T, s *harness.Server, token, path string) []string {
	t.Helper()
	env := restExpect(t, s, token, http.MethodGet, path, nil, http.StatusOK)
	var data struct {
		Invitations []json.RawMessage `json:"invitations"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		t.Fatalf("decode invitations: %v\nraw: %s", err, env.Raw)
	}
	out := make([]string, 0, len(data.Invitations))
	for _, inv := range data.Invitations {
		out = append(out, string(inv))
	}
	return out
}

func requireNoInvitationFor(t *testing.T, s *harness.Server, token, path, email string) {
	t.Helper()
	for _, inv := range projectInvitations(t, s, token, path) {
		if strings.Contains(inv, `"`+email+`"`) {
			t.Fatalf("a refused invitation left a record behind for %s: %s", email, inv)
		}
	}
}

func requireInvitationWithRole(t *testing.T, s *harness.Server, token, path, email, role string) {
	t.Helper()
	for _, inv := range projectInvitations(t, s, token, path) {
		if strings.Contains(inv, `"`+email+`"`) && strings.Contains(inv, `"`+role+`"`) {
			return
		}
	}
	t.Fatalf("no invitation for %s with role %s in %s", email, role, filepath.Base(path))
}

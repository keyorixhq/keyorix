//go:build e2e

package journeys

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

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
// "Nothing is created" is asserted by reading what was stored, not by the retry: the
// project leg reads the project's invitation list, and the global leg (no REST route
// lists project-0 invitations) counts the email's project_invitations rows in the
// journey server's own database. A retry for the same email with a valid role is then
// accepted, but that alone proves nothing: there is no duplicate-pending check, so a
// stray row would not turn the retry into a 409.
//
// Not covered here: the SSO just-in-time refusal leg (a default_role the scope guard
// refuses) needs a real Keycloak in Docker -- pending e2e VM.

func TestJourney_InvitationRoleScope_SQLite(t *testing.T) {
	serverBin, _ := harness.BuildBinaries(t)
	s := harness.StartServer(t, serverBin, harness.DBBackend{Name: "sqlite"})
	t.Cleanup(s.Close)

	dbPath := filepath.Join(s.Dir, "keyorix.db")
	runInvitationRoleScope(t, s, func(t *testing.T, email string) int {
		t.Helper()
		stmt := fmt.Sprintf("SELECT COUNT(*) FROM project_invitations WHERE project_id = 0 AND email = '%s';", email)
		out, err := sqliteCLI(dbPath, stmt).CombinedOutput() // #nosec G204 -- this test's own tempdir DB path and a constant email
		if err != nil {
			t.Fatalf("sqlite3 %q: %v\n%s", stmt, err, out)
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(out)))
		if err != nil {
			t.Fatalf("sqlite3 %q: not a count: %q", stmt, out)
		}
		return n
	})
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

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open journey database: %v", err)
	}
	if sqlDB, err := db.DB(); err == nil {
		t.Cleanup(func() { _ = sqlDB.Close() })
	}
	runInvitationRoleScope(t, s, func(t *testing.T, email string) int {
		t.Helper()
		var n int64
		if err := db.Raw("SELECT COUNT(*) FROM project_invitations WHERE project_id = 0 AND email = ?", email).Scan(&n).Error; err != nil {
			t.Fatalf("count global invitations for %s: %v", email, err)
		}
		return int(n)
	})
}

// globalInvitationCount returns how many global (project 0) invitation rows the
// server stored for email, read from its database: no REST route lists them.
type globalInvitationCount func(t *testing.T, email string) int

func runInvitationRoleScope(t *testing.T, s *harness.Server, globalInvites globalInvitationCount) {
	t.Helper()
	adminToken := mfaLogin(t, s, "smoketestadmin", harness.BootstrapAdminPassword)

	restExpect(t, s, adminToken, http.MethodPost, "/api/v1/projects",
		map[string]string{"name": "invite-scope"}, http.StatusCreated)
	projID := projectID(t, s, adminToken, "invite-scope")
	projectInvites := fmt.Sprintf("/api/v1/projects/%d/invitations", projID)

	// Two subtests, so a failure in one leg still runs the other.
	t.Run("project invitations", func(t *testing.T) {
		for _, role := range []string{"system_admin", "system_viewer"} {
			email := role + "-on-project@example.com"
			env := restCall(t, s, adminToken, http.MethodPost, projectInvites,
				map[string]string{"email": email, "role": role})
			if env.StatusCode != http.StatusBadRequest {
				t.Fatalf("install-wide role %s offered on a project invitation: want 400, got %d: %s", role, env.StatusCode, env.Raw)
			}
			requireNoInvitationFor(t, s, adminToken, projectInvites, email)

			// The corrected retry for the same email goes through (requireNoInvitationFor
			// above is the "nothing created" proof; a stray row would not refuse this).
			restExpect(t, s, adminToken, http.MethodPost, projectInvites,
				map[string]string{"email": email, "role": "project_viewer"}, http.StatusCreated)
		}

		for _, role := range []string{"project_viewer", "viewer", "admin"} {
			email := role + "-ok@example.com"
			restExpect(t, s, adminToken, http.MethodPost, projectInvites,
				map[string]string{"email": email, "role": role}, http.StatusCreated)
			requireInvitationWithRole(t, s, adminToken, projectInvites, email, role)
		}
	})

	t.Run("global invitation", func(t *testing.T) {
		const globalEmail = "global-project-role@example.com"
		env := restCall(t, s, adminToken, http.MethodPost, "/api/v1/invitations",
			map[string]string{"email": globalEmail, "role": "project_viewer"})
		// Stored rows are checked before the status, so a server that both accepts the
		// role and stores the row (as before #3546) fails on the row, not only the 201.
		if n := globalInvites(t, globalEmail); n != 0 {
			t.Errorf("a refused global invitation left %d record(s) behind for %s", n, globalEmail)
		}
		if env.StatusCode != http.StatusBadRequest {
			t.Fatalf("project-tier role offered on a global invitation: want 400, got %d: %s", env.StatusCode, env.Raw)
		}
		// The corrected retry is accepted, and the same count now sees exactly its row, so
		// the zero above is a real read of the table the invitation lands in.
		restExpect(t, s, adminToken, http.MethodPost, "/api/v1/invitations",
			map[string]string{"email": globalEmail, "role": "system_viewer"}, http.StatusCreated)
		if n := globalInvites(t, globalEmail); n != 1 {
			t.Fatalf("after the accepted global invitation for %s: want 1 record, got %d", globalEmail, n)
		}
	})
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

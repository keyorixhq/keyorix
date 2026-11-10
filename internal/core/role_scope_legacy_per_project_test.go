package core

// role_scope_legacy_per_project_test.go — #3605 / #3588: the legacy single-tier
// roles (admin, editor, viewer, auditor, super_admin) are assignable "global"
// only, ending the "any" of #3546 Phase 2 (ask 3546-phase2-legacy-roles-scope).
// A new grant of one at a project is refused and names the project role to use;
// a grant already held at a project is not touched, keeps working and is listed
// for replacement.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestLegacyRolesAreGlobalOnly pins the decision itself, by literal, so flipping
// the seed table back (one line) fails here and not only in callers.
func TestLegacyRolesAreGlobalOnly(t *testing.T) {
	want := map[string]string{"admin": "project_admin", "super_admin": "project_admin",
		"editor": "project_developer", "viewer": "project_viewer", "auditor": "project_auditor"}
	require.Equal(t, want, models.LegacyRoleProjectReplacements)
	for name, replacement := range want {
		require.Equal(t, models.RoleAssignableGlobal, models.BuiltinRoleAssignableScopes[name],
			"legacy role %s must be install-wide only (#3605)", name)
		require.Equal(t, models.RoleAssignableProject, models.BuiltinRoleAssignableScopes[replacement],
			"the replacement of %s must be a project role", name)

		err := validateRoleScope(&models.Role{Name: name, AssignableScope: models.RoleAssignableGlobal}, Scope{ProjectID: 3})
		require.ErrorIs(t, err, ErrRoleScopeInvalid)
		msg, ok := RoleScopeClientMessage(err)
		require.True(t, ok)
		require.Contains(t, msg, "role "+name+" is install-wide")
		require.Contains(t, msg, "grant "+replacement+" on the project instead")
	}
}

// TestLegacyRolesGrantedPerProjectAreRefused drives the per-project grants of
// legacy roles that #3546 Phase 2 kept working, to machine identities, users and
// groups, and reads the grant rows back: refused, nothing written, and the
// refusal names the replacement. Before #3605 every one of these succeeded.
func TestLegacyRolesGrantedPerProjectAreRefused(t *testing.T) {
	c, _ := newBootstrappedCore(t)
	ctx := context.Background()
	w := newRoleScopeWorld(t, c)
	viewer, err := c.storage.GetRoleByName(ctx, "viewer")
	require.NoError(t, err)
	legacyAdmin, err := c.storage.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	requireRefused := func(t *testing.T, err error, replacement string) {
		t.Helper()
		require.ErrorIs(t, err, ErrRoleScopeInvalid)
		msg, ok := RoleScopeClientMessage(err)
		require.True(t, ok)
		require.Contains(t, msg, replacement)
	}

	t.Run("machine identities", func(t *testing.T) {
		m, err := c.CreateMachineIdentity(ctx, w.p1, "ci-reader", MachineTypeService, "", "", w.adminID, 0)
		require.NoError(t, err)
		scope := Scope{ProjectID: w.p1}
		// machine grant-role ci-reader --project rs-one --role viewer
		requireRefused(t, c.AssignMachineRole(ctx, m.ID, viewer.ID, scope, w.adminID, false), "project_viewer")
		requireRefused(t, c.AssignMachineRole(ctx, m.ID, legacyAdmin.ID, scope, w.adminID, false), "project_admin")
		got, err := c.storage.GetMachineRoleIDsAt(ctx, m.ID, scope)
		require.NoError(t, err)
		require.Empty(t, got)

		// The replacement is what a machine gets instead.
		projectViewer, err := c.storage.GetRoleByName(ctx, "project_viewer")
		require.NoError(t, err)
		require.NoError(t, c.AssignMachineRole(ctx, m.ID, projectViewer.ID, scope, w.adminID, false))
		got, err = c.storage.GetMachineRoleIDsAt(ctx, m.ID, scope)
		require.NoError(t, err)
		require.Equal(t, []uint{projectViewer.ID}, got)
	})

	t.Run("users and groups", func(t *testing.T) {
		before := w.grantRows(t)
		// rbac assign-role --user alice@example.com --role viewer --project rs-one (local CLI path)
		requireRefused(t, c.AssignUserRoleScoped(ctx, "alice@example.com", "viewer", Scope{ProjectID: w.p1}), "project_viewer")
		// POST /api/v1/user-roles {role: admin, project_id: rs-two}
		requireRefused(t, c.AssignUserRole(ctx, w.adminID, w.userID, legacyAdmin.ID, Scope{ProjectID: w.p2}, false), "project_admin")
		requireRefused(t, c.AssignRoleToGroup(ctx, w.adminID, w.groupID, viewer.ID, Scope{ProjectID: w.p1}, false), "project_viewer")
		require.ElementsMatch(t, before, w.grantRows(t), "a refused grant writes nothing")

		// Install-wide grants of the same roles are still accepted.
		require.NoError(t, c.AssignUserRole(ctx, w.adminID, w.userID, viewer.ID, Scope{}, false))
		require.Contains(t, w.grantRows(t), fmtGrant("user", w.userID, viewer.ID, 0, 0))
	})
}

// TestExistingLegacyProjectGrantsKeepWorkingAndAreListed: grants written before
// #3605 (straight into storage, as an older release left them) keep authorizing,
// survive a role-set write that does not add them, and are listed with how to
// replace them; the check itself changes nothing.
func TestExistingLegacyProjectGrantsKeepWorkingAndAreListed(t *testing.T) {
	c, _ := newBootstrappedCore(t)
	ctx := context.Background()
	w := newRoleScopeWorld(t, c)
	viewer, err := c.storage.GetRoleByName(ctx, "viewer")
	require.NoError(t, err)
	editor, err := c.storage.GetRoleByName(ctx, "editor")
	require.NoError(t, err)
	projectViewer, err := c.storage.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	m, err := c.CreateMachineIdentity(ctx, w.p1, "ci-reader", MachineTypeService, "", "", w.adminID, 0)
	require.NoError(t, err)
	inP1, inE1 := Scope{ProjectID: w.p1}, Scope{ProjectID: w.p1, EnvironmentID: w.e1}
	require.NoError(t, c.storage.AssignRole(ctx, w.userID, viewer.ID, inP1))
	require.NoError(t, c.storage.AssignRoleToGroup(ctx, w.groupID, editor.ID, inE1))
	require.NoError(t, c.storage.AssignMachineRole(ctx, m.ID, viewer.ID, inP1))

	ok, err := c.Authorize(ctx, w.userID, permSecretsRead, inP1)
	require.NoError(t, err)
	require.True(t, ok, "an existing per-project grant of a legacy role keeps working")
	before := w.grantRows(t)

	got, err := c.ListLegacyRoleProjectGrants(ctx)
	require.NoError(t, err)
	require.Len(t, got, 3)
	report := LegacyRoleProjectGrantReport(got, 0)
	t.Logf("upgrade check:\n%s", strings.Join(report, "\n"))
	require.Len(t, report, 4)
	require.Contains(t, report[0], "3 existing per-project grant(s) of a legacy role")
	require.Contains(t, report[0], "use project_auditor where that access is needed", "viewer's audit.read is called out")
	require.Equal(t, "group devs holds editor on project rs-one, environment rs-e1; replace with project_developer: "+
		"keyorix rbac assign-role-to-group --group devs --role project_developer --project rs-one --environment rs-e1 && "+
		"keyorix rbac remove-role-from-group --group devs --role editor --project rs-one --environment rs-e1", report[1])
	require.Equal(t, "machine ci-reader holds viewer on project rs-one; replace with project_viewer: "+
		"keyorix machine grant-role ci-reader --project rs-one --role project_viewer && "+
		"keyorix machine revoke-role ci-reader --project rs-one --role viewer", report[2])
	require.Equal(t, "user alice@example.com holds viewer on project rs-one; replace with project_viewer: "+
		"keyorix rbac assign-role --user alice@example.com --role project_viewer --project rs-one && "+
		"keyorix rbac remove-role --user alice@example.com --role viewer --project rs-one", report[3])
	require.ElementsMatch(t, before, w.grantRows(t), "the check is read-only")

	// A write that keeps the grant is not a new assignment.
	require.NoError(t, c.SetUserRoles(ctx, w.adminID, w.userID, []uint{viewer.ID}, inP1, false))
	require.Contains(t, w.grantRows(t), fmtGrant("user", w.userID, viewer.ID, w.p1, 0))
	// Replacing it through the same write is the documented way out.
	require.NoError(t, c.SetUserRoles(ctx, w.adminID, w.userID, []uint{projectViewer.ID}, inP1, false))
	rows := w.grantRows(t)
	require.Contains(t, rows, fmtGrant("user", w.userID, projectViewer.ID, w.p1, 0))
	require.NotContains(t, rows, fmtGrant("user", w.userID, viewer.ID, w.p1, 0))
}

// TestLegacyRoleProjectGrantReport covers what a real install rarely produces:
// the line limit, an unresolved principal or project, an environment-scoped
// machine grant (the CLI has no flag for it), a time-bound grant and a name that
// needs quoting.
func TestLegacyRoleProjectGrantReport(t *testing.T) {
	require.Nil(t, LegacyRoleProjectGrantReport(nil, 0), "no grants, no report")
	base := LegacyRoleProjectGrant{PrincipalType: "machine", PrincipalID: 9, Principal: "bot", RoleName: "admin",
		Replacement: "project_admin", ProjectID: 2, Project: "payments"}

	hint := func(mod func(*LegacyRoleProjectGrant)) string {
		g := base
		mod(&g)
		return g.ReplaceHint()
	}
	require.Contains(t, hint(func(g *LegacyRoleProjectGrant) { g.Principal = "" }), "through the API")
	require.Contains(t, hint(func(g *LegacyRoleProjectGrant) { g.Project = "" }), "authorizes nothing")
	require.Contains(t, hint(func(g *LegacyRoleProjectGrant) { g.EnvironmentID, g.Environment = 5, "dev" }), "no environment flag")
	require.Contains(t, hint(func(g *LegacyRoleProjectGrant) {
		g.PrincipalType, g.Principal = "group", "ops; rm -rf ~"
	}), `--group 'ops; rm -rf ~' --role project_admin`)

	exp := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	timed := base
	timed.PrincipalType, timed.Principal, timed.ExpiresAt = "user", "a@example.com", &exp
	require.Contains(t, timed.Describe(), "expires 2026-12-01T00:00:00Z")
	require.Contains(t, timed.ReplaceHint(), "add --ttl")

	many := make([]LegacyRoleProjectGrant, 5)
	for i := range many {
		many[i] = base
	}
	lines := LegacyRoleProjectGrantReport(many, 2)
	require.Len(t, lines, 4)
	require.Contains(t, lines[3], "and 3 more")
	require.NotContains(t, lines[0], "project_auditor", "only called out when a viewer grant is listed")
	require.Len(t, LegacyRoleProjectGrantReport(many, 0), 6, "0 names every grant")
}

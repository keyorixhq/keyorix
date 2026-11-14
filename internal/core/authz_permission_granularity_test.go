package core_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPermissionGranularity_DistinctPermissionsEnforced pins that each permission in the
// lattice (read vs write vs delete, and read vs assign across resources) is enforced
// independently — a holder of one must not get an adjacent one. A regression here is a
// privilege-escalation vector (e.g. a read-only auditor granting itself roles). Uses
// NON-admin roles only; super_admin/admin bypass granular checks by design.
func TestPermissionGranularity_DistinctPermissionsEnforced(t *testing.T) {
	t.Parallel()
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()

	// Legacy roles are install-wide only (#3605), so the project grants below use
	// project-tier roles. project_viewer has the legacy viewer bundle. The legacy
	// editor and auditor bundles differ from project_developer (which also deletes)
	// and project_auditor (reads secrets, no roles.read), and this test asserts on
	// exactly those differences, so they are kept as project-tier custom roles.
	editorRole := h.CreateProjectRoleWithPermissions(t, "gran-editor-role", 301, "secrets.read", "secrets.write", "users.read")
	auditorRole := h.CreateProjectRoleWithPermissions(t, "gran-auditor-role", 302,
		"audit.read", "audit.admin", "system.read", "users.read", "roles.read")

	viewer := h.CreateTestUser(t, "gran-viewer", 300) // secrets.read, users.read
	h.AssignUserRole(t, viewer.ID, testhelper.RoleProjectViewer, ptr(1))
	editor := h.CreateTestUser(t, "gran-editor", 301) // + secrets.write
	h.AssignUserRole(t, editor.ID, editorRole.ID, ptr(1))
	auditor := h.CreateTestUser(t, "gran-auditor", 302) // audit.read, roles.read, users.read, system.read
	h.AssignUserRole(t, auditor.ID, auditorRole.ID, ptr(1))

	cases := []struct {
		name       string
		userID     uint
		permission string
		want       bool
	}{
		// viewer — read only on secrets, nothing on writes/deletes/users.
		{"viewer reads secrets", viewer.ID, "secrets.read", true},
		{"viewer cannot write secrets", viewer.ID, "secrets.write", false},
		{"viewer cannot delete secrets", viewer.ID, "secrets.delete", false},
		{"viewer cannot write users", viewer.ID, "users.write", false},
		// editor — read + write, but write must not imply delete.
		{"editor writes secrets", editor.ID, "secrets.write", true},
		{"editor cannot delete secrets", editor.ID, "secrets.delete", false},
		// auditor — roles.read must not imply roles.assign (the escalation guard),
		// and an auditor has no secrets access at all.
		{"auditor reads roles", auditor.ID, "roles.read", true},
		{"auditor cannot assign roles", auditor.ID, "roles.assign", false},
		{"auditor cannot read secrets", auditor.ID, "secrets.read", false},
	}

	ctx := context.Background()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := h.CoreService.Authorize(ctx, tc.userID, tc.permission, core.Scope{ProjectID: 1})
			require.NoError(t, err)
			assert.Equal(t, tc.want, ok)
		})
	}
}

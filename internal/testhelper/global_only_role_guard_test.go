package testhelper

// global_only_role_guard_test.go — the fixture guard of RBACTestHelper.AssignUserRole /
// AssignGroupRole: a global-only role (the legacy super_admin/admin/editor/viewer/
// auditor, the system_* roles) is not grantable at a project (#3605), so a fixture that
// does it tests a grant no install can hold. The predicate is checked against the roles
// the helper seeds; the helper's own t.Fatalf path is the same predicate.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestGlobalOnlyAtProject_SeededRoles(t *testing.T) {
	h := NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)

	role := func(id uint) *models.Role {
		var r models.Role
		require.NoError(t, h.DB.First(&r, id).Error)
		return &r
	}
	for _, id := range []uint{1, 2, 3, 4, 5, 6} { // the legacy roles and system_viewer
		assert.True(t, globalOnlyAtProject(role(id), 1), "role %d (%s) is install-wide only", id, role(id).Name)
		assert.False(t, globalOnlyAtProject(role(id), 0), "role %d (%s) is grantable at the global scope", id, role(id).Name)
	}
	for _, id := range []uint{RoleProjectAdmin, RoleProjectDeveloper, RoleProjectViewer, RoleProjectAuditor} {
		assert.False(t, globalOnlyAtProject(role(id), 1), "role %d (%s) is a project role", id, role(id).Name)
	}

	// A custom role made by the helper gets the new-role default (project): fail closed
	// for a global grant elsewhere, but never refused at a project here.
	h.CreateTestRole(t, "deployers", "custom", 90)
	assert.False(t, globalOnlyAtProject(role(90), 1))
}

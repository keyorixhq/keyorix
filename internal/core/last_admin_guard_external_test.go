package core_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Removing the last global install-admin must be refused (it would strand the
// install with no one able to administer it); once a second global admin exists,
// removing the first is allowed again.
func TestRemoveUserRole_RefusesLastGlobalAdmin(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	ctx := context.Background()

	const superAdminRoleID = uint(1) // seeded by the helper
	h.CreateTestUser(t, "root", 100)
	h.CreateTestUser(t, "root2", 101)
	h.AssignUserRole(t, 100, superAdminRoleID, nil) // global super_admin

	// User 100 is the only global admin → removal refused.
	err := h.CoreService.RemoveUserRole(ctx, 0, 100, superAdminRoleID, core.Scope{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "last install administrator")

	// FIX-2: a project-scoped admin removal is now guarded too (previously it
	// fell straight through to storage.RemoveRole with no last-admin check at
	// all — recoverable by a global admin, but still an availability risk this
	// fix now refuses outright, mirroring SetProjectMemberRole/
	// RemoveProjectMember's identical stance for direct grants).
	h.AssignUserRole(t, 100, superAdminRoleID, ptrUint(2))
	err = h.CoreService.RemoveUserRole(ctx, 0, 100, superAdminRoleID, core.Scope{ProjectID: 2})
	require.Error(t, err, "user 100 is project 2's only roles.assign holder")
	assert.Contains(t, err.Error(), "last administrator")

	// Once a second project admin exists, the first can be removed.
	h.AssignUserRole(t, 101, superAdminRoleID, ptrUint(2))
	require.NoError(t, h.CoreService.RemoveUserRole(ctx, 0, 100, superAdminRoleID, core.Scope{ProjectID: 2}),
		"a project-scoped admin role can be removed once another project admin survives")

	// Add a SECOND global admin; now the first can be removed.
	h.AssignUserRole(t, 101, superAdminRoleID, nil)
	require.NoError(t, h.CoreService.RemoveUserRole(ctx, 0, 100, superAdminRoleID, core.Scope{}),
		"removing one global admin is fine while another remains")

	// But now 101 is the last one → refused again.
	err = h.CoreService.RemoveUserRole(ctx, 0, 101, superAdminRoleID, core.Scope{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "last install administrator")
}

func ptrUint(v uint) *uint { return &v }

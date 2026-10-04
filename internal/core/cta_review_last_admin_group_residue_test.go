package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestCTAReview_RemoveUserRole_LastGlobalAdmin_AfterAdminGroupDeleted
// (C-GUARD2-EXEMPT-REVIEW, #2658): removing the last direct global admin must
// be refused once the only other admin grant belongs to a group that has been
// deleted. RemoveUserRole's storage-level guard (ListGlobalAdminAssignmentsForUpdate)
// counts any group_roles admin row as a surviving admin without checking that
// the group is live or has active members, so this succeeds today and the
// install reaches zero admins — serially, no race involved.
func TestCTAReview_RemoveUserRole_LastGlobalAdmin_AfterAdminGroupDeleted(t *testing.T) {
	t.Skip("open gap #2658: RemoveUserRole counts a deleted group's admin grant as a surviving admin; un-skip in the fixing PR")
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	admin, err := st.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)

	var adminRoleID uint
	ids, err := st.GetUserRoleIDsExact(ctx, admin.ID, storage.Scope{})
	require.NoError(t, err)
	for _, id := range ids {
		if c.installAdminRoleIDSet(ctx)[id] {
			adminRoleID = id
		}
	}
	require.NotZero(t, adminRoleID, "bootstrap admin must hold a global install-admin role directly")

	member, err := st.CreateUser(ctx, &models.User{Username: "cta-gadmin", Email: "cta-gadmin@example.com", IsActive: true, AccountState: AccountActive, PasswordHash: "x"})
	require.NoError(t, err)
	g, err := st.CreateGroup(ctx, &models.Group{Name: "cta-admins", NameFolded: "cta-admins"})
	require.NoError(t, err)
	require.NoError(t, st.AssignRoleToGroup(ctx, g.ID, adminRoleID, storage.Scope{}))
	require.NoError(t, st.AddUserToGroup(ctx, member.ID, g.ID, 0))

	// The direct admin still exists, so deleting the admin group is allowed.
	require.NoError(t, c.DeleteGroup(ctx, admin.ID, g.ID))

	err = c.RemoveUserRole(ctx, admin.ID, admin.ID, adminRoleID, Scope{})
	stillAdmin, aerr := c.IsGlobalAdmin(ctx, admin.ID)
	require.NoError(t, aerr)
	t.Logf("RemoveUserRole(last direct admin) after DeleteGroup: err=%v, still global admin=%v", err, stillAdmin)
	assert.Error(t, err, "removing the last real global admin must be refused")
	assert.True(t, stillAdmin, "the install must not be left with zero global admins")
}

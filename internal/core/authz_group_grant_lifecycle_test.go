package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Lifecycle boundaries on the GROUP-inheritance authorization path
// (GetUserGroupRoleIDsAt — the two-join query: user_groups ⋈ group_roles ⋈ groups).
// The cross-tenant suite already pins direct-grant expiry and soft-deleted-group
// revocation; these pin the boundaries unique to a group-inherited grant that nothing
// else covers: a time-bound (JIT) GROUP grant must stop authorizing the instant it
// expires, a far-future GROUP grant must still authorize (the filter rejects expiry, not
// every dated grant), and revoking a user's group membership must drop the inherited
// role. Each drives the real scope SQL through a live SQLite store, so a regression that
// dropped the group_roles.expires_at filter or the membership join would fail here.

// TestCrossTenant_ExpiredGroupGrantExcluded mirrors the direct-grant expiry test on the
// group path: a group carries an EXPIRED editor (read+write) grant and a PERMANENT viewer
// (read) grant at the same scope. Reads still resolve via the permanent grant; writes came
// only from the expired editor grant and must be denied.
func TestCrossTenant_ExpiredGroupGrantExcluded(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	u := h.CreateTestUser(t, "groupjit", 210)
	g := h.CreateTestGroup(t, "jitgroup", "", 60)
	h.AssignUserToGroup(t, u.ID, g.ID)

	past := time.Now().Add(-1 * time.Hour)
	// EXPIRED editor grant to the group, plus a PERMANENT viewer grant, both at project 1.
	require.NoError(t, h.DB.Create(&models.GroupRole{
		GroupID: g.ID, RoleID: roleEditor, ProjectID: 1, ExpiresAt: &past,
	}).Error)
	h.AssignGroupRole(t, g.ID, roleViewer, ptr(1))

	ctx := context.Background()
	ok, err := h.CoreService.Authorize(ctx, u.ID, "secrets.read", core.Scope{ProjectID: 1})
	require.NoError(t, err)
	assert.True(t, ok, "the permanent group viewer grant still authorizes reads")

	ok, err = h.CoreService.Authorize(ctx, u.ID, "secrets.write", core.Scope{ProjectID: 1})
	require.NoError(t, err)
	assert.False(t, ok, "write came only from the EXPIRED group editor grant — it must be denied")
}

// TestCrossTenant_FutureGroupGrantStillAuthorizes is the positive control for the expiry
// filter: a group grant with an expiry far in the future must authorize. Without this, a
// regression that denied any dated grant (e.g. flipping the comparison) would pass the
// expired-grant test yet silently break legitimate just-in-time access.
func TestCrossTenant_FutureGroupGrantStillAuthorizes(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	u := h.CreateTestUser(t, "groupfuture", 211)
	g := h.CreateTestGroup(t, "futuregroup", "", 61)
	h.AssignUserToGroup(t, u.ID, g.ID)

	future := time.Now().Add(24 * time.Hour)
	require.NoError(t, h.DB.Create(&models.GroupRole{
		GroupID: g.ID, RoleID: roleEditor, ProjectID: 1, ExpiresAt: &future,
	}).Error)

	ctx := context.Background()
	ok, err := h.CoreService.Authorize(ctx, u.ID, "secrets.write", core.Scope{ProjectID: 1})
	require.NoError(t, err)
	assert.True(t, ok, "a group grant expiring in the future must still authorize")
}

// TestCrossTenant_GroupMembershipRevocationRevokesRole pins the membership join: a user
// inherits a role only while they are a member of the group. Removing the user_groups row
// (membership revocation — not a soft delete; the row is gone) must immediately drop the
// inherited role, even though the group and its grant remain.
func TestCrossTenant_GroupMembershipRevocationRevokesRole(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	u := h.CreateTestUser(t, "exgroupmember", 212)
	g := h.CreateTestGroup(t, "keepgroup", "", 62)
	h.AssignUserToGroup(t, u.ID, g.ID)
	h.AssignGroupRole(t, g.ID, roleEditor, ptr(1))

	ctx := context.Background()
	ok, err := h.CoreService.Authorize(ctx, u.ID, "secrets.write", core.Scope{ProjectID: 1})
	require.NoError(t, err)
	require.True(t, ok, "precondition: the user has access via group membership")

	// Revoke membership — the group and its role grant are untouched.
	require.NoError(t, h.DB.Where("user_id = ? AND group_id = ?", u.ID, g.ID).Delete(&models.UserGroup{}).Error)

	ok, err = h.CoreService.Authorize(ctx, u.ID, "secrets.write", core.Scope{ProjectID: 1})
	require.NoError(t, err)
	assert.False(t, ok, "a removed group member must lose the group-inherited role")
}

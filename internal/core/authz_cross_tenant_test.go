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

// Adversarial cross-tenant tests that pin the authorization scope boundary against
// regression: a grant at one project must never authorize at another, an expired
// grant must never authorize, and a soft-deleted group must stop conferring its
// roles. These drive the REAL scope SQL (GetUserRoleIDsAt / GetUserGroupRoleIDsAt /
// GetMachineRoleIDsAt) through a live SQLite store, not mocks — so a future change to
// a WHERE clause that opened a cross-tenant leak would fail here.
//
// (roleEditor/roleViewer/ptr are defined in authz_scoped_test.go, same package.)

func TestCrossTenant_GroupRoleDoesNotLeakToOtherProject(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	u := h.CreateTestUser(t, "groupie", 200)
	g := h.CreateTestGroup(t, "team-p1", "editors on p1", 50)
	h.AssignUserToGroup(t, u.ID, g.ID)
	h.AssignGroupRole(t, g.ID, roleEditor, ptr(1)) // group is editor on project 1 only

	ctx := context.Background()
	ok, err := h.CoreService.Authorize(ctx, u.ID, "secrets.write", core.Scope{ProjectID: 1})
	require.NoError(t, err)
	assert.True(t, ok, "group-inherited editor should write in the group's project")

	ok, err = h.CoreService.Authorize(ctx, u.ID, "secrets.write", core.Scope{ProjectID: 2})
	require.NoError(t, err)
	assert.False(t, ok, "a group-inherited role must NOT leak to another project")
}

func TestCrossTenant_SoftDeletedGroupRevokesInheritedRole(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	u := h.CreateTestUser(t, "exmember", 201)
	g := h.CreateTestGroup(t, "doomed", "", 51)
	h.AssignUserToGroup(t, u.ID, g.ID)
	h.AssignGroupRole(t, g.ID, roleEditor, ptr(1))

	ctx := context.Background()
	ok, err := h.CoreService.Authorize(ctx, u.ID, "secrets.write", core.Scope{ProjectID: 1})
	require.NoError(t, err)
	require.True(t, ok, "precondition: the user has access via the group")

	require.NoError(t, h.DB.Delete(&models.Group{}, g.ID).Error) // soft-delete the group

	ok, err = h.CoreService.Authorize(ctx, u.ID, "secrets.write", core.Scope{ProjectID: 1})
	require.NoError(t, err)
	assert.False(t, ok, "a soft-deleted group must stop conferring its roles")
}

func TestCrossTenant_ExpiredGrantExcludedAlongsidePermanent(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	u := h.CreateTestUser(t, "mixedgrants", 202)
	past := time.Now().Add(-1 * time.Hour)
	// An EXPIRED editor (read+write) and a PERMANENT viewer (read) at the SAME scope.
	require.NoError(t, h.DB.Create(&models.UserRole{
		UserID: u.ID, RoleID: roleEditor, ProjectID: 1, ExpiresAt: &past,
	}).Error)
	h.AssignUserRole(t, u.ID, roleViewer, ptr(1))

	ctx := context.Background()
	ok, err := h.CoreService.Authorize(ctx, u.ID, "secrets.read", core.Scope{ProjectID: 1})
	require.NoError(t, err)
	assert.True(t, ok, "the permanent viewer grant still authorizes reads")

	ok, err = h.CoreService.Authorize(ctx, u.ID, "secrets.write", core.Scope{ProjectID: 1})
	require.NoError(t, err)
	assert.False(t, ok, "write came only from the EXPIRED editor grant — it must be denied")
}

func TestCrossTenant_MachineIdentityDeniedOtherProject(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.MachineIdentity{}, &models.MachineIdentityRole{}))
	require.NoError(t, h.DB.Create(&models.MachineIdentity{ID: 70, ProjectID: 1, Name: "ci", State: "active"}).Error)
	require.NoError(t, h.DB.Create(&models.MachineIdentityRole{MachineIdentityID: 70, RoleID: roleEditor, ProjectID: 1}).Error)

	ctx := context.Background()
	ok, err := h.CoreService.AuthorizePrincipal(ctx, core.ActorTypeMachine, 70, "secrets.read", core.Scope{ProjectID: 1})
	require.NoError(t, err)
	assert.True(t, ok, "the machine should read in its own project")

	// Machines get no admin bypass, so the scope boundary is the whole containment:
	// a leaked machine token must not reach another project's secrets.
	ok, err = h.CoreService.AuthorizePrincipal(ctx, core.ActorTypeMachine, 70, "secrets.read", core.Scope{ProjectID: 2})
	require.NoError(t, err)
	assert.False(t, ok, "a machine scoped to project 1 must NOT read project 2 (cross-project IDOR)")
}

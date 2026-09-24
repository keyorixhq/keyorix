// last_admin_guard_wiring_test.go — #G02 regressions: guardLastAdminDeactivation
// and its group-membership/group-delete counterparts were correct where they
// were called, but several demotion/removal paths were added without calling
// them. Each test below simulates a single-global-admin install and asserts
// the previously-unguarded path now refuses to strip the install's last
// administrator, mirroring the existing guardLastAdminDeactivation coverage
// in scim_guards_test.go.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSuspendUser_RefusesLastAdminDeactivation(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10}).Error) // global admin

	err := c.SuspendUser(ctx, 9, 1)
	require.Error(t, err, "must refuse to suspend the install's last global administrator")
	assert.Contains(t, err.Error(), "last install administrator")
}

func TestSuspendUser_AllowsWhenAnotherAdminExists(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "root2", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 10}).Error)
	// S1 (CLI-split inventory #2012): actor 9 must itself be an admin for the
	// admin-rank ceiling to permit suspending target 1 (also an admin).
	require.NoError(t, db.Create(&models.User{ID: 9, Username: "acting-admin", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 9, RoleID: 10}).Error)

	err := c.SuspendUser(ctx, 9, 1)
	require.NoError(t, err, "suspending one of two admins is allowed")
}

func TestUpdateUser_RefusesLastAdminDeactivation(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", Email: "root@x.io", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10}).Error)

	no := false
	// S1b (CLI-split inventory #2012): self-deactivation via UpdateUser is now
	// refused UNCONDITIONALLY (ErrCannotActOnSelf), before guardLastAdminDeactivation
	// is ever reached -- a strictly broader guard than "only when you're the
	// last admin." For root (the install's sole admin) targeting themselves,
	// this test's original scenario, that broader guard is what actually
	// fires now: reaching guardLastAdminDeactivation via UpdateUser at all
	// requires a non-self actor who ALSO satisfies the admin-rank ceiling --
	// which, for a target that's genuinely the LAST admin, is structurally
	// impossible (a second ceiling-satisfying actor would mean a second
	// admin exists, and the guard would then correctly ALLOW the
	// deactivation instead of refusing it). See
	// TestSuspendUser_RefusesLastAdminDeactivation (above) for that guard's
	// own coverage via a non-self actor -- SuspendUser calls
	// guardLastAdminDeactivation OUTSIDE and before setAccountState's
	// ceiling check, so an unprivileged actor still reaches it there;
	// UpdateUser's deactivating branch checks the ceiling first.
	_, err := c.UpdateUser(ctx, &UpdateUserRequest{ID: 1, ActorID: 1, IsActive: &no})
	require.Error(t, err, "must refuse to deactivate the install's last global administrator via UpdateUser")
	assert.ErrorIs(t, err, ErrCannotActOnSelf)
}

func TestUpdateUser_AllowsDeactivationWhenAnotherAdminExists(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", Email: "root@x.io", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "root2", Email: "root2@x.io", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 10}).Error)

	no := false
	// S1 (CLI-split inventory #2012): ActorID: 2 -- the OTHER admin performing
	// the deactivation, who must (and does, via the bypass role) satisfy the
	// admin-rank ceiling against target 1.
	updated, err := c.UpdateUser(ctx, &UpdateUserRequest{ID: 1, ActorID: 2, IsActive: &no})
	require.NoError(t, err, "deactivating one of two admins via UpdateUser is allowed")
	assert.False(t, updated.IsActive)
}

func TestDeprovisionSCIMGroup_RefusesWhenGroupHoldsLastAdmin(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive, ExternalID: "okta|root"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Keyorix-Admins"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 5, RoleID: 10}).Error) // group confers admin, globally
	require.NoError(t, db.Create(&models.UserGroup{UserID: 1, GroupID: 5}).Error)

	err := c.DeprovisionSCIMGroup(ctx, 9, 5)
	require.Error(t, err, "must refuse to delete a group holding the install's last route to admin authority")

	// The group must still exist — the guard must run BEFORE the delete.
	_, getErr := c.storage.GetGroup(ctx, 5)
	require.NoError(t, getErr, "group must not have been deleted when the guard refuses")
}

func TestDeprovisionSCIMGroup_AllowsWhenGroupConfersNoAdmin(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Engineering"}).Error)

	err := c.DeprovisionSCIMGroup(ctx, 9, 5)
	require.NoError(t, err, "deleting a non-admin-bearing group must still work")
}

func TestReplaceSCIMGroup_RefusesRemovingLastAdminMember(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive, ExternalID: "okta|root"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Keyorix-Admins"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 5, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 1, GroupID: 5}).Error)

	// PUT with an empty member list — removes user 1, the install's only admin route.
	_, err := c.ReplaceSCIMGroup(ctx, 9, 5, "", nil)
	require.Error(t, err, "must refuse a SCIM PUT that would strip the install's last admin-group membership")

	members, mErr := c.storage.ListGroupMembers(ctx, 5)
	require.NoError(t, mErr)
	require.Len(t, members, 1, "the membership must not have been removed when the guard refuses")
}

func TestPatchSCIMGroup_RefusesRemovingLastAdminMember(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive, ExternalID: "okta|root"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Keyorix-Admins"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 5, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 1, GroupID: 5}).Error)

	_, err := c.PatchSCIMGroup(ctx, 9, 5, nil, nil, []uint{1})
	require.Error(t, err, "must refuse a SCIM PATCH remove that would strip the install's last admin-group membership")

	members, mErr := c.storage.ListGroupMembers(ctx, 5)
	require.NoError(t, mErr)
	require.Len(t, members, 1, "the membership must not have been removed when the guard refuses")
}

func TestPatchSCIMGroup_AllowsRemovingMemberWhenAnotherAdminExists(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive, ExternalID: "okta|root"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "root2", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Keyorix-Admins"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 5, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 1, GroupID: 5}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 10}).Error) // independent admin route

	_, err := c.PatchSCIMGroup(ctx, 9, 5, nil, nil, []uint{1})
	require.NoError(t, err, "removing one admin route is fine when another survives")

	members, mErr := c.storage.ListGroupMembers(ctx, 5)
	require.NoError(t, mErr)
	assert.Empty(t, members)
}

// TestSetAccountState_ReactivationBypassesLastAdminGuardByConstruction
// documents docs/design-b2-recover-admin.md §3/§6's own adversarial-review
// item: "recover-admin interaction with GuardLastAdminDeactivation: confirm
// recovery re-activation is unaffected by (does not need to bypass) that
// guard." `keyorix-server admin recover-admin` (server/admin package —
// cannot be imported from here; it depends on internal/core, not the
// reverse) deliberately calls storage.Storage.SetAccountState DIRECTLY, the
// exact same primitive setAccountState (account_state.go) wraps with
// guardLastAdminDeactivation — never through core.ReactivateUser or any
// other core.KeyorixCore method. This test pins the structural fact that
// makes the guard's non-involvement true BY CONSTRUCTION, not by re-tracing
// every call site by hand whenever this file changes: the raw storage
// primitive has no guard logic of its own, so reactivating even the
// install's LAST (and only) admin via SetAccountState directly always
// succeeds — there is no check to route around, because storage.Storage
// never had one. guardLastAdminDeactivation exists specifically to protect
// DEACTIVATION paths (see this file's own header comment); recovery only
// ever calls the REACTIVATION direction of this exact primitive.
func TestSetAccountState_ReactivationBypassesLastAdminGuardByConstruction(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountSuspended}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10}).Error) // the ONLY global admin, currently suspended

	err := c.storage.SetAccountState(ctx, 1, AccountPasswordResetRequired, time.Now())
	require.NoError(t, err, "reactivating the install's only admin via the raw storage primitive must never be refused")
}

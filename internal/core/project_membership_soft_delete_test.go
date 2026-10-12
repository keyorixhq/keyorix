// project_membership_soft_delete_test.go — follow-up item 3, plus the item-4 cases
// that belong at the core layer: what a membership view does when the thing the grant
// points at is no longer live.
//
// A project-scoped role grant deliberately SURVIVES a soft-delete, so RestoreProject
// can reinstate it, and GetUserRoleScopes does not filter deleted projects. That left
// two surfaces wrong in opposite directions:
//
//   - the admin Users list COUNTED a soft-deleted project, so "3 projects" included
//     one nobody can navigate to;
//   - the per-user membership LIST reported the row with an EMPTY project name,
//     because the name came from ListProjects, which GORM soft-delete-scopes.
//
// The two surfaces now answer differently, on purpose: a headline count answers "how
// many projects is this person in" and a deleted project is not one, while an access
// review answers "what grants exist" and that grant does. Each half is asserted here,
// and each asserts the OTHER surface's behaviour too, so a future change that
// collapses them back together fails.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// softDeleteProject soft-deletes a project the way DeleteProject does, without
// pulling in the rest of that path's side effects.
func softDeleteProject(t *testing.T, db *gorm.DB, projectID uint) {
	t.Helper()
	require.NoError(t, db.Model(&models.Project{}).Where("id = ?", projectID).
		Update("deleted_at", time.Now().UTC()).Error)
	// Precondition: the soft-delete really is invisible to the ordinary lister, which
	// is what used to blank the name.
	var live []*models.Project
	require.NoError(t, db.Find(&live).Error)
	for _, p := range live {
		require.NotEqual(t, projectID, p.ID, "the soft-deleted project must be out of the default scope")
	}
}

// TestListProjectMembershipsForUser_SoftDeletedProjectIsNamedAndFlagged is item 3's
// list half. The grant survives, so the row must survive — identifiably.
func TestListProjectMembershipsForUser_SoftDeletedProjectIsNamedAndFlagged(t *testing.T) {
	t.Parallel()
	c, db := membershipDefinitionFixture(t)
	seedMembershipWorld(t, db)
	ctx := context.Background()

	// Member of both projects; project 2 is then soft-deleted.
	for _, pid := range []uint{1, 2} {
		require.NoError(t, db.Create(&models.UserRole{
			UserID: 1, RoleID: roleIDByName(t, db, "project_viewer"), ProjectID: pid,
		}).Error)
	}
	softDeleteProject(t, db, 2)

	got, err := c.ListProjectMembershipsForUser(ctx, 1)
	require.NoError(t, err)
	require.Len(t, got, 2, "the grant on the soft-deleted project is real and survives a restore — report it")

	byID := map[uint]UserProjectMembership{}
	for _, m := range got {
		byID[m.ProjectID] = m
	}

	live := byID[1]
	assert.Equal(t, "payments-api", live.ProjectName)
	assert.False(t, live.ProjectDeleted)

	deleted := byID[2]
	assert.True(t, deleted.ProjectDeleted,
		"a membership of a soft-deleted project must say so — an auditor cannot act on a row that "+
			"looks identical to a live one")
	assert.Equal(t, "billing", deleted.ProjectName,
		"and it must carry the project's REAL name: it used to come back empty, because the name was "+
			"resolved through the soft-delete-scoped lister")
}

// TestProjectMembershipCounts_ExcludesSoftDeletedProjects is item 3's count half.
func TestProjectMembershipCounts_ExcludesSoftDeletedProjects(t *testing.T) {
	t.Parallel()
	c, db := membershipDefinitionFixture(t)
	seedMembershipWorld(t, db)
	ctx := context.Background()

	for _, pid := range []uint{1, 2} {
		require.NoError(t, db.Create(&models.UserRole{
			UserID: 1, RoleID: roleIDByName(t, db, "project_viewer"), ProjectID: pid,
		}).Error)
	}

	// Before the delete: both count. This is the positive control — without it, the
	// assertion below would pass against a counter that is broken for everything.
	before, err := c.ProjectMembershipCounts(ctx, []uint{1})
	require.NoError(t, err)
	require.Equal(t, 2, before[1].Active, "fixture control: two live memberships")

	softDeleteProject(t, db, 2)

	after, err := c.ProjectMembershipCounts(ctx, []uint{1})
	require.NoError(t, err)
	assert.Equal(t, 1, after[1].Active,
		"a soft-deleted project is not a project this user is in — counting it shows an admin a number "+
			"they cannot reconcile with anything clickable on screen")
	assert.Equal(t, 1, after[1].Total,
		"and it is not pending onboarding either, so Total drops with it")

	// The LIST still shows it, flagged. The two surfaces differ deliberately, and
	// asserting both here is what stops a later change from collapsing them.
	rows, err := c.ListProjectMembershipsForUser(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, rows, 2, "the review surface keeps the row; only the headline count drops it")
}

// TestProjectMembershipCounts_ExcludesVanishedProject covers the other not-live case:
// a grant pointing at a project ID that is not in the index at all (hard-deleted, or
// a stale row). It must not inflate the count either, and it must not error.
func TestProjectMembershipCounts_ExcludesVanishedProject(t *testing.T) {
	t.Parallel()
	c, db := membershipDefinitionFixture(t)
	seedMembershipWorld(t, db)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.UserRole{
		UserID: 1, RoleID: roleIDByName(t, db, "project_viewer"), ProjectID: 1,
	}).Error)
	// A grant on a project that does not exist.
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 1, RoleID: roleIDByName(t, db, "project_viewer"), ProjectID: 9999,
	}).Error)

	counts, err := c.ProjectMembershipCounts(ctx, []uint{1})
	require.NoError(t, err, "a dangling grant must not fail the whole page of counts")
	assert.Equal(t, 1, counts[1].Active, "only the real, live project counts")
}

// TestListProjectMembershipsForUser_SuspendedUserStillHoldsTheirGrants is one of
// item 4's cases. Account state and RBAC are separate axes: suspending a user blocks
// LOGIN, it does not revoke their grants. An access review must still show what they
// hold, or a reviewer would believe a suspended account carries no access — and the
// last-admin guard's own "live holders, not grant rows" rule (INV-CORE-15) exists
// precisely because those are different questions.
func TestListProjectMembershipsForUser_SuspendedUserStillHoldsTheirGrants(t *testing.T) {
	t.Parallel()
	c, db := membershipDefinitionFixture(t)
	seedMembershipWorld(t, db)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.UserRole{
		UserID: 1, RoleID: roleIDByName(t, db, "project_viewer"), ProjectID: 1,
	}).Error)
	require.NoError(t, db.Model(&models.User{}).Where("id = ?", 1).
		Updates(map[string]any{"is_active": false, "account_state": AccountSuspended}).Error)

	got, err := c.ListProjectMembershipsForUser(ctx, 1)
	require.NoError(t, err)
	require.Len(t, got, 1,
		"suspension blocks login, not RBAC — the grant is still there and a reviewer must see it, "+
			"which is the same distinction INV-CORE-15 draws between live holders and grant rows")
	assert.Equal(t, uint(1), got[0].ProjectID)

	counts, err := c.ProjectMembershipCounts(ctx, []uint{1})
	require.NoError(t, err)
	assert.Equal(t, 1, counts[1].Active, "and the count agrees with the list")
}

// TestListProjectMembershipsForUser_SoftDeletedGroupConfersNothing is item 4's
// group case, and it is the one that must NOT be generous: a soft-deleted group's
// group_roles rows are still in the table, and GetUserRoleScopes' own join excludes
// them. Pinned here because the membership view would otherwise be the one surface
// that resurrected a deleted group's authority.
func TestListProjectMembershipsForUser_SoftDeletedGroupConfersNothing(t *testing.T) {
	t.Parallel()
	c, db := membershipDefinitionFixture(t)
	seedMembershipWorld(t, db)
	ctx := context.Background()

	g := &models.Group{Name: "payments-oncall"}
	require.NoError(t, db.Create(g).Error)
	require.NoError(t, db.Create(&models.UserGroup{UserID: 1, GroupID: g.ID}).Error)
	require.NoError(t, db.Create(&models.GroupRole{
		GroupID: g.ID, RoleID: roleIDByName(t, db, "project_viewer"), ProjectID: 1,
	}).Error)

	// Control: while the group is live, the membership IS reported.
	live, err := c.ListProjectMembershipsForUser(ctx, 1)
	require.NoError(t, err)
	require.Len(t, live, 1, "fixture control: a live group confers the membership")
	require.True(t, live[0].ViaGroup)

	require.NoError(t, db.Model(&models.Group{}).Where("id = ?", g.ID).
		Update("deleted_at", time.Now().UTC()).Error)

	got, err := c.ListProjectMembershipsForUser(ctx, 1)
	require.NoError(t, err)
	assert.Empty(t, got,
		"a soft-deleted group confers no authority, so it confers no membership either — its "+
			"group_roles rows are still in the table, which is why this needs asserting")

	counts, err := c.ProjectMembershipCounts(ctx, []uint{1})
	require.NoError(t, err)
	assert.Equal(t, 0, counts[1].Active, "and the count agrees")
}

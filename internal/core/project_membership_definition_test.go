// project_membership_definition_test.go — #2781's behaviour tests.
//
// These run against a real LocalStorage on SQLite, not a mock, deliberately: the
// claim #2781 is about is that the per-USER membership view and the per-PROJECT
// members view agree, and that can only be shown by driving both through the same
// storage queries over the same rows. A mock would let the test assert whatever
// shape the test author imagined rather than what the queries return.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// membershipDefinitionFixture opens an isolated in-memory SQLite DB with every
// model the membership path touches, and returns a core backed by it.
func membershipDefinitionFixture(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{},
		&models.Permission{}, &models.RolePermission{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{},
		// SecretNode: the membership path resolves project names via
		// ListProjectsWithCounts (so a SOFT-DELETED project's name and flag come
		// back rather than an empty string), and that query LEFT JOINs secret_nodes
		// for its per-project count. Needed even though no secret is seeded.
		&models.SecretNode{},
		&models.ProjectMembership{}, &models.AuditEvent{},
	))
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

// seedMembershipWorld creates two users, two projects and the four ADR-021 roles,
// and returns nothing — tests address rows by the IDs SQLite assigns in order
// (users 1..2, projects 1..2), asserted below so a seeding change fails loudly.
func seedMembershipWorld(t *testing.T, db *gorm.DB) {
	t.Helper()
	for _, u := range []*models.User{
		{Username: "alice", Email: "alice@example.com"},
		{Username: "bob", Email: "bob@example.com"},
	} {
		require.NoError(t, db.Create(u).Error)
	}
	for _, p := range []*models.Project{{Name: "payments-api"}, {Name: "billing"}} {
		require.NoError(t, db.Create(p).Error)
	}
	for _, r := range []*models.Role{
		{Name: "project_viewer"}, {Name: "project_admin"}, {Name: "system_viewer"},
	} {
		require.NoError(t, db.Create(r).Error)
	}
	var alice models.User
	require.NoError(t, db.Where("username = ?", "alice").First(&alice).Error)
	require.Equal(t, uint(1), alice.ID, "fixture assumes alice is user 1")
	var payments models.Project
	require.NoError(t, db.Where("name = ?", "payments-api").First(&payments).Error)
	require.Equal(t, uint(1), payments.ID, "fixture assumes payments-api is project 1")
}

func roleIDByName(t *testing.T, db *gorm.DB, name string) uint {
	t.Helper()
	var r models.Role
	require.NoError(t, db.Where("name = ?", name).First(&r).Error)
	return r.ID
}

// TestListProjectMembershipsForUser_GrantWithNoJournalRow is the #2781 regression:
// the shape the web UI produces — POST /projects/{id}/members writes a role grant
// and NO ADR-022 journal row — used to make this view report "not a member of any
// project". It must report the membership, as active.
//
// Red before the fix (the view read storage.ListUserProjectMemberships, which has
// no row here, so it returned []); green after.
func TestListProjectMembershipsForUser_GrantWithNoJournalRow(t *testing.T) {
	t.Parallel()
	c, db := membershipDefinitionFixture(t)
	seedMembershipWorld(t, db)
	ctx := context.Background()

	// Exactly what AddProjectMember -> AssignUserRole persists, and nothing else:
	// no project_memberships row anywhere.
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 1, RoleID: roleIDByName(t, db, "project_viewer"), ProjectID: 1,
	}).Error)
	var journalRows int64
	require.NoError(t, db.Model(&models.ProjectMembership{}).Count(&journalRows).Error)
	require.Zero(t, journalRows, "fixture precondition: the ADR-022 journal is empty, as it is on a UI-driven install")

	got, err := c.ListProjectMembershipsForUser(ctx, 1)
	require.NoError(t, err)
	require.Len(t, got, 1, "a project-scoped grant with no journal row IS a membership (#2781)")
	assert.Equal(t, uint(1), got[0].ProjectID)
	assert.Equal(t, "payments-api", got[0].ProjectName)
	assert.Equal(t, "project_viewer", got[0].Role)
	assert.Equal(t, []string{"project_viewer"}, got[0].Roles)
	assert.Equal(t, MembershipActive, got[0].State, "a live grant with no journal row is active, not \"\"")
	assert.False(t, got[0].ViaGroup)
}

// TestListProjectMembershipsForUser_AgreesWithProjectMembersView is the property
// #2781 is actually about: the per-user view and the per-project view must not
// contradict each other. Asserted over the same rows, in both directions.
func TestListProjectMembershipsForUser_AgreesWithProjectMembersView(t *testing.T) {
	t.Parallel()
	c, db := membershipDefinitionFixture(t)
	seedMembershipWorld(t, db)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.UserRole{
		UserID: 1, RoleID: roleIDByName(t, db, "project_admin"), ProjectID: 1,
	}).Error)
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 2, RoleID: roleIDByName(t, db, "project_viewer"), ProjectID: 1,
	}).Error)

	members, err := c.ListProjectMembers(ctx, 1)
	require.NoError(t, err)
	require.Len(t, members, 2, "Project -> Members lists both users")

	// Every user the project says is a member, says the project is one of theirs.
	for _, m := range members {
		mine, lerr := c.ListProjectMembershipsForUser(ctx, m.UserID)
		require.NoError(t, lerr)
		found := false
		for _, row := range mine {
			if row.ProjectID == 1 {
				found = true
				assert.Equal(t, m.RoleName, row.Role,
					"the two views must agree on user %d's role at project 1", m.UserID)
			}
		}
		assert.True(t, found, "user %d is listed in Project -> Members but their own view omits project 1", m.UserID)
	}

	// And nobody claims a membership the project does not list.
	mine, err := c.ListProjectMembershipsForUser(ctx, 1)
	require.NoError(t, err)
	require.Len(t, mine, 1, "alice is a member of exactly the one project she holds a grant in")
}

// TestListProjectMembershipsForUser_GlobalGrantIsNotMembership pins the half of the
// definition that is load-bearing for break-glass and per-secret ACLs: an
// install-wide grant (project_id = 0) makes nobody a member of any project. Without
// it, every SSO/JIT user holding the system_viewer baseline would read as a member
// of everything.
//
// This must hold before AND after the fix — it is the invariant, not the change.
func TestListProjectMembershipsForUser_GlobalGrantIsNotMembership(t *testing.T) {
	t.Parallel()
	c, db := membershipDefinitionFixture(t)
	seedMembershipWorld(t, db)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.UserRole{
		UserID: 1, RoleID: roleIDByName(t, db, "system_viewer"), ProjectID: 0,
	}).Error)

	got, err := c.ListProjectMembershipsForUser(ctx, 1)
	require.NoError(t, err)
	assert.Empty(t, got, "a global (project_id = 0) grant is not membership of any project")

	for _, pid := range []uint{1, 2} {
		isMember, merr := c.IsProjectMember(ctx, 1, pid)
		require.NoError(t, merr)
		assert.False(t, isMember, "global grant must not make user 1 a member of project %d", pid)
	}
}

// TestListProjectMembershipsForUser_NoAccessSeesNothing is the other direction of
// the brief's rule: a user with no grant anywhere must see no project, before and
// after. A fix that made the per-user view generous would show up here.
func TestListProjectMembershipsForUser_NoAccessSeesNothing(t *testing.T) {
	t.Parallel()
	c, db := membershipDefinitionFixture(t)
	seedMembershipWorld(t, db)
	ctx := context.Background()

	// bob (user 2) holds nothing; alice holds project 1 — so the world is not empty,
	// which is what makes bob's empty result meaningful rather than vacuous.
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 1, RoleID: roleIDByName(t, db, "project_admin"), ProjectID: 1,
	}).Error)

	got, err := c.ListProjectMembershipsForUser(ctx, 2)
	require.NoError(t, err)
	assert.Empty(t, got, "a user with no project-scoped grant must see no project")

	isMember, err := c.IsProjectMember(ctx, 2, 1)
	require.NoError(t, err)
	assert.False(t, isMember)
}

// TestListProjectMembershipsForUser_ViaGroupIsAttributed covers the group-inherited
// case. It matters operationally: an admin who sees this membership and goes to the
// project's Members tab to remove it will not find a row to remove, because the
// grant belongs to the group.
func TestListProjectMembershipsForUser_ViaGroupIsAttributed(t *testing.T) {
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

	got, err := c.ListProjectMembershipsForUser(ctx, 1)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, uint(1), got[0].ProjectID)
	assert.Equal(t, "project_viewer", got[0].Role)
	assert.True(t, got[0].ViaGroup, "a membership held only through a group must say so")

	isMember, err := c.IsProjectMember(ctx, 1, 1)
	require.NoError(t, err)
	assert.True(t, isMember, "a group-inherited project grant is membership")
}

// TestListProjectMembershipsForUser_ExpiredGrantIsNotMembership pins that a lapsed
// time-bound grant (an expired break-glass project_admin, say) confers neither
// access nor membership — the same expires_at filter every authorization query
// applies. A membership view that ignored expiry would keep showing a revoked
// reviewer as a current member.
func TestListProjectMembershipsForUser_ExpiredGrantIsNotMembership(t *testing.T) {
	t.Parallel()
	c, db := membershipDefinitionFixture(t)
	seedMembershipWorld(t, db)
	ctx := context.Background()

	past := time.Now().UTC().Add(-time.Hour)
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 1, RoleID: roleIDByName(t, db, "project_admin"), ProjectID: 1, ExpiresAt: &past,
	}).Error)

	got, err := c.ListProjectMembershipsForUser(ctx, 1)
	require.NoError(t, err)
	assert.Empty(t, got, "an expired grant is not membership")

	isMember, err := c.IsProjectMember(ctx, 1, 1)
	require.NoError(t, err)
	assert.False(t, isMember)
}

// TestListProjectMembershipsForUser_JournalSuppliesLifecycleState is the other half
// of the design: the ADR-022 journal keeps its job (the invite lifecycle) as an
// annotation on a membership the grant already established.
func TestListProjectMembershipsForUser_JournalSuppliesLifecycleState(t *testing.T) {
	t.Parallel()
	c, db := membershipDefinitionFixture(t)
	seedMembershipWorld(t, db)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.UserRole{
		UserID: 1, RoleID: roleIDByName(t, db, "project_viewer"), ProjectID: 1,
	}).Error)
	// A journal row whose state is NOT active, alongside a live grant: exactly the
	// INV-CORE-44 violation an admin must be able to see, rather than have smoothed
	// over into "active".
	require.NoError(t, db.Create(&models.ProjectMembership{
		ProjectID: 1, UserID: 1, Role: "project_viewer",
		State: MembershipProvisioned, InvitedAt: time.Now().UTC(),
	}).Error)

	got, err := c.ListProjectMembershipsForUser(ctx, 1)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, MembershipProvisioned, got[0].State,
		"the journal's state must be surfaced as-is, not normalised away")
}

// TestProjectMembershipCounts_CountsGrantsNotJournalRows replaces
// TestProjectMembershipCounts_Delegates (see account_state_stale_test.go for why
// that one is gone). The admin Users list's project column is the second screen the
// journal made lie, and the one place HTTP and gRPC both read it.
func TestProjectMembershipCounts_CountsGrantsNotJournalRows(t *testing.T) {
	t.Parallel()
	c, db := membershipDefinitionFixture(t)
	seedMembershipWorld(t, db)
	ctx := context.Background()

	// alice: two grants, no journal rows (the UI-driven shape).
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 1, RoleID: roleIDByName(t, db, "project_admin"), ProjectID: 1,
	}).Error)
	require.NoError(t, db.Create(&models.UserRole{
		UserID: 1, RoleID: roleIDByName(t, db, "project_viewer"), ProjectID: 2,
	}).Error)
	// bob: no grant, one invite still in flight — Total counts it, Active does not.
	require.NoError(t, db.Create(&models.ProjectMembership{
		ProjectID: 1, UserID: 2, Role: "project_viewer",
		State: MembershipInvited, InvitedAt: time.Now().UTC(),
	}).Error)

	got, err := c.ProjectMembershipCounts(ctx, []uint{1, 2})
	require.NoError(t, err)

	assert.Equal(t, 2, got[1].Active, "alice is a member of both projects she holds grants in")
	assert.Equal(t, 2, got[1].Total, "no pending onboarding for alice, so Total == Active")
	assert.Equal(t, 0, got[2].Active, "bob holds no grant, so he is a member of nothing")
	assert.Equal(t, 1, got[2].Total, "bob's in-flight invite still counts toward Total")
}

// TestProjectMembershipCounts_GlobalGrantDoesNotCount is the counts view's half of
// the global-grant invariant: the install baseline must not inflate anyone's
// project count to "every project" or to 1.
func TestProjectMembershipCounts_GlobalGrantDoesNotCount(t *testing.T) {
	t.Parallel()
	c, db := membershipDefinitionFixture(t)
	seedMembershipWorld(t, db)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.UserRole{
		UserID: 1, RoleID: roleIDByName(t, db, "system_viewer"), ProjectID: 0,
	}).Error)

	got, err := c.ProjectMembershipCounts(ctx, []uint{1})
	require.NoError(t, err)
	assert.Equal(t, 0, got[1].Active)
	assert.Equal(t, 0, got[1].Total)
}

// TestIsProjectMember_ProjectZeroIsNeverMembership pins the sentinel explicitly,
// because break_glass.go depends on it: project_id 0 is the global scope, not a
// project, and asking "is this user a member of project 0" must be false rather
// than "yes, they hold the install baseline".
func TestIsProjectMember_ProjectZeroIsNeverMembership(t *testing.T) {
	t.Parallel()
	c, db := membershipDefinitionFixture(t)
	seedMembershipWorld(t, db)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.UserRole{
		UserID: 1, RoleID: roleIDByName(t, db, "system_viewer"), ProjectID: 0,
	}).Error)

	isMember, err := c.IsProjectMember(ctx, 1, 0)
	require.NoError(t, err)
	assert.False(t, isMember, "project 0 is the global-scope sentinel, never a project")
}

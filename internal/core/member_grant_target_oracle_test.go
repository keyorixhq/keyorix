package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// OWNERSHIP-ORACLE-1 item 2: the user-ID-keyed onboarding paths (AddProjectMember,
// SetProjectMemberRole for a new member, InviteMember, AddUserToGroup) ran the
// membership domain allowlist check, which loads the TARGET user, before the
// granter ceiling (requireGranterHoldsRolePermissions). A roles.assign holder who
// may not grant the role could therefore tell from the refusal whether a user ID
// exists anywhere in the install and whether its email is on the allowlist. The
// ceiling now runs first; an actor it refuses gets the same answer for every
// target.

// memberOracleFixture is a bootstrapped core with the domain allowlist on, a
// project, and an actor holding a role that bundles roles.assign alone at that
// project (the route gate of every path here) and globally (the group routes'
// gate). That actor passes the route gate but may not grant project_viewer, which
// bundles more than roles.assign.
type memberOracleFixture struct {
	c       *KeyorixCore
	st      *store.LocalStorage
	actor   uint
	group   uint
	targets map[string]uint
}

const memberOracleProject = uint(7)

func newMemberOracleFixture(t *testing.T) memberOracleFixture {
	t.Helper()
	ctx := context.Background()
	c, st := newBootstrappedCore(t)
	db := st.DB()
	seedLiveScopeProjects(t, db, memberOracleProject)
	c.SetMembershipDomainAllowlist([]string{"allowed.com"})

	var perm models.Permission
	require.NoError(t, db.Where("name = ?", "roles.assign").First(&perm).Error)
	mgr := models.Role{Name: "member-manager-oracle"}
	require.NoError(t, db.Create(&mgr).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: mgr.ID, PermissionID: perm.ID}).Error)

	actor, err := st.CreateUser(ctx, foldedTestUser(t, "oracle-actor", "oracle-actor@allowed.com"))
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, actor.ID, mgr.ID, storage.Scope{ProjectID: memberOracleProject}))
	require.NoError(t, st.AssignRole(ctx, actor.ID, mgr.ID, storage.Scope{}))

	allowed, err := st.CreateUser(ctx, foldedTestUser(t, "oracle-allowed", "oracle-allowed@allowed.com"))
	require.NoError(t, err)
	offList, err := st.CreateUser(ctx, foldedTestUser(t, "oracle-offlist", "oracle-offlist@evil.com"))
	require.NoError(t, err)

	viewer, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	g, err := st.CreateGroup(ctx, &models.Group{Name: "oracle-project-group"})
	require.NoError(t, err)
	require.NoError(t, st.AssignRoleToGroup(ctx, g.ID, viewer.ID, storage.Scope{ProjectID: memberOracleProject}))

	return memberOracleFixture{
		c: c, st: st, actor: actor.ID, group: g.ID,
		targets: map[string]uint{"existing user": allowed.ID, "missing user": 999999, "off-allowlist user": offList.ID},
	}
}

// TestMemberGrants_UnauthorizedActorGetsIdenticalRefusal: for each onboarding
// path, an actor the ceiling refuses gets the same typed refusal and text for an
// existing allowed user, a missing user ID and a user off the allowlist, and
// nothing is written.
func TestMemberGrants_UnauthorizedActorGetsIdenticalRefusal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	ops := map[string]func(f memberOracleFixture, target uint) error{
		"AddProjectMember": func(f memberOracleFixture, target uint) error {
			return f.c.AddProjectMember(ctx, f.actor, memberOracleProject, target, "project_viewer", false)
		},
		"SetProjectMemberRole": func(f memberOracleFixture, target uint) error {
			return f.c.SetProjectMemberRole(ctx, f.actor, memberOracleProject, target, "project_viewer", false)
		},
		"InviteMember": func(f memberOracleFixture, target uint) error {
			_, err := f.c.InviteMember(ctx, memberOracleProject, target, "project_viewer", f.actor, 0, false)
			return err
		},
		"AddUserToGroup": func(f memberOracleFixture, target uint) error {
			return f.c.AddUserToGroup(ctx, f.actor, false, target, f.group, memberOracleProject)
		},
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newMemberOracleFixture(t)
			refusals := map[string]string{}
			for label, target := range f.targets {
				err := op(f, target)
				require.Error(t, err, label)
				assert.ErrorIs(t, err, ErrPermissionDenied, "%s: %v", label, err)
				refusals[label] = err.Error()

				roles, rerr := f.st.GetUserRoleIDsExact(ctx, target, storage.Scope{ProjectID: memberOracleProject})
				require.NoError(t, rerr)
				assert.Empty(t, roles, "%s: a refused grant wrote a role", label)
				m, _ := f.st.GetActiveProjectMembership(ctx, memberOracleProject, target)
				assert.Nil(t, m, "%s: a refused invite wrote a membership", label)
				groups, gerr := f.st.GetUserGroups(ctx, target)
				require.NoError(t, gerr)
				assert.Empty(t, groups, "%s: a refused join wrote a membership", label)
			}
			first := refusals["existing user"]
			for label, r := range refusals {
				assert.Equal(t, first, r, "%s: refusal differs by target user: %q", label, refusals)
			}
		})
	}
}

// TestMemberGrants_AuthorizedActorKeepsSpecificErrors pins the other half: an
// actor the ceiling allows still gets the allowlist and not-found answers.
func TestMemberGrants_AuthorizedActorKeepsSpecificErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newMemberOracleFixture(t)
	admin := uint(4242)
	grantGlobalAdmin(t, f.st, admin)

	err := f.c.AddProjectMember(ctx, admin, memberOracleProject, f.targets["off-allowlist user"], "project_viewer", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not on the allowlist")

	err = f.c.SetProjectMemberRole(ctx, admin, memberOracleProject, f.targets["missing user"], "project_viewer", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	_, err = f.c.InviteMember(ctx, memberOracleProject, f.targets["off-allowlist user"], "project_viewer", admin, 0, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not on the allowlist")

	err = f.c.AddUserToGroup(ctx, admin, false, f.targets["off-allowlist user"], f.group, memberOracleProject)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not on the allowlist")

	require.NoError(t, f.c.AddProjectMember(ctx, admin, memberOracleProject, f.targets["existing user"], "project_viewer", false))
}

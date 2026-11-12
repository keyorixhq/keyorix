package core

// role_set_ceiling_every_requested_role_test.go — FU-OWNERSHIP-1 (ask
// ownership-oracle-1-role-set-noop-oracle, answer a).
//
// SetProjectMemberRole and SetUserRoles judged the granter ceiling only on the roles
// a request ADDED. A roles.assign holder who may not grant role X got success when
// the target already held X (a no-op, or a request that only removed other roles) and
// a refusal otherwise, so the answer said which roles the target held. The ceiling is
// now judged on every requested role first: the answer no longer depends on the
// target's role set, and a refused request changes nothing.

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

type roleSetCeilingOp struct {
	name  string
	scope Scope
	role  string
	call  func(ctx context.Context, f memberOracleFixture, actor, target, roleID uint) error
}

func roleSetCeilingOps() []roleSetCeilingOp {
	project := Scope{ProjectID: memberOracleProject}
	setUserRoles := func(scope Scope) func(context.Context, memberOracleFixture, uint, uint, uint) error {
		return func(ctx context.Context, f memberOracleFixture, actor, target, roleID uint) error {
			return f.c.SetUserRoles(ctx, actor, target, []uint{roleID}, scope, false)
		}
	}
	return []roleSetCeilingOp{
		{"SetProjectMemberRole", project, "project_viewer", func(ctx context.Context, f memberOracleFixture, actor, target, _ uint) error {
			return f.c.SetProjectMemberRole(ctx, actor, memberOracleProject, target, "project_viewer", false)
		}},
		{"SetUserRoles project scope", project, "project_viewer", setUserRoles(project)},
		{"SetUserRoles global scope", Scope{}, "system_viewer", setUserRoles(Scope{})},
	}
}

// emptyRoleForCeilingTest creates a role bundling no permissions: any roles.assign
// holder may grant it, so it is the "other role" a target can hold.
func emptyRoleForCeilingTest(t *testing.T, f memberOracleFixture) uint {
	t.Helper()
	r := models.Role{Name: "ceiling-empty-role", NameFolded: "ceiling-empty-role"}
	require.NoError(t, f.st.DB().Create(&r).Error)
	return r.ID
}

func ceilingTestUser(t *testing.T, f memberOracleFixture, name string) uint {
	t.Helper()
	u, err := f.st.CreateUser(context.Background(), foldedTestUser(t, name, name+"@allowed.com"))
	require.NoError(t, err)
	return u.ID
}

// TestRoleSetReplace_CeilingRefusal_SameForEveryTargetRoleSet: an actor who may not
// grant the requested role is refused with the same typed error and text whatever the
// target holds, including the no-op and narrowing shapes that used to succeed.
func TestRoleSetReplace_CeilingRefusal_SameForEveryTargetRoleSet(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, op := range roleSetCeilingOps() {
		t.Run(op.name, func(t *testing.T) {
			t.Parallel()
			f := newMemberOracleFixture(t)
			role, err := f.st.GetRoleByName(ctx, op.role)
			require.NoError(t, err)
			other := emptyRoleForCeilingTest(t, f)

			held := map[string][]uint{
				"no role":              nil,
				"another role":         {other},
				"exactly the role":     {role.ID},
				"the role and another": {role.ID, other},
			}
			refusals := map[string]string{}
			i := 0
			for label, roles := range held {
				i++
				target := ceilingTestUser(t, f, fmt.Sprintf("ceiling-target-%d", i))
				for _, id := range roles {
					require.NoError(t, f.st.AssignRole(ctx, target, id, op.scope), label)
				}

				err := op.call(ctx, f, f.actor, target, role.ID)
				require.ErrorIs(t, err, ErrPermissionDenied, "%s: %v", label, err)
				refusals[label] = err.Error()

				after, rerr := f.st.GetUserRoleIDsExact(ctx, target, op.scope)
				require.NoError(t, rerr)
				assert.ElementsMatch(t, roles, after, "%s: a refused request changed the role set", label)
			}
			first := refusals["no role"]
			for label, r := range refusals {
				assert.Equal(t, first, r, "%s: the refusal depends on the target's roles: %q", label, refusals)
			}
		})
	}
}

// TestRoleSetReplace_CeilingRefusal_PrecedesScopeCheck: the role-scope refusal looks
// only at roles the target does not hold yet, so running it first would also vary
// with the target's role set.
func TestRoleSetReplace_CeilingRefusal_PrecedesScopeCheck(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newMemberOracleFixture(t)
	viewer, err := f.st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	other := emptyRoleForCeilingTest(t, f)

	member := ceilingTestUser(t, f, "ceiling-scope-member")
	require.NoError(t, f.st.AssignRole(ctx, member, other, Scope{ProjectID: memberOracleProject}))
	err = f.c.SetProjectMemberRole(ctx, f.actor, memberOracleProject, member, "system_viewer", false)
	require.ErrorIs(t, err, ErrPermissionDenied, "system_viewer is not valid on a project: %v", err)

	err = f.c.SetUserRoles(ctx, f.actor, member, []uint{viewer.ID}, Scope{}, false)
	require.ErrorIs(t, err, ErrPermissionDenied, "project_viewer is not valid at global scope: %v", err)
}

// TestRoleSetReplace_GranterWhoCanGrantKeepsNoOpAndNarrowing pins the other half: an
// actor who may grant the requested role still gets the no-op and the narrowing, and
// only REQUESTED roles are judged, so removing a role the actor could not grant works
// when what stays is within the ceiling.
func TestRoleSetReplace_GranterWhoCanGrantKeepsNoOpAndNarrowing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, op := range roleSetCeilingOps() {
		t.Run(op.name, func(t *testing.T) {
			t.Parallel()
			f := newMemberOracleFixture(t)
			role, err := f.st.GetRoleByName(ctx, op.role)
			require.NoError(t, err)
			other := emptyRoleForCeilingTest(t, f)
			require.NoError(t, f.st.AssignRole(ctx, f.actor, role.ID, op.scope), "the actor now holds the role's permissions")

			noop := ceilingTestUser(t, f, "ceiling-noop")
			require.NoError(t, f.st.AssignRole(ctx, noop, role.ID, op.scope))
			require.NoError(t, op.call(ctx, f, f.actor, noop, role.ID))
			after, err := f.st.GetUserRoleIDsExact(ctx, noop, op.scope)
			require.NoError(t, err)
			assert.Equal(t, []uint{role.ID}, after)

			narrow := ceilingTestUser(t, f, "ceiling-narrow")
			require.NoError(t, f.st.AssignRole(ctx, narrow, role.ID, op.scope))
			require.NoError(t, f.st.AssignRole(ctx, narrow, other, op.scope))
			require.NoError(t, op.call(ctx, f, f.actor, narrow, role.ID))
			after, err = f.st.GetUserRoleIDsExact(ctx, narrow, op.scope)
			require.NoError(t, err)
			assert.Equal(t, []uint{role.ID}, after)
		})
	}

	t.Run("removing a role beyond the ceiling", func(t *testing.T) {
		t.Parallel()
		f := newMemberOracleFixture(t)
		scope := Scope{ProjectID: memberOracleProject}
		viewer, err := f.st.GetRoleByName(ctx, "project_viewer")
		require.NoError(t, err)
		other := emptyRoleForCeilingTest(t, f)

		target := ceilingTestUser(t, f, "ceiling-remove-beyond")
		require.NoError(t, f.st.AssignRole(ctx, target, viewer.ID, scope))
		require.NoError(t, f.st.AssignRole(ctx, target, other, scope))
		require.NoError(t, f.c.SetUserRoles(ctx, f.actor, target, []uint{other}, scope, false))
		after, err := f.st.GetUserRoleIDsExact(ctx, target, scope)
		require.NoError(t, err)
		assert.Equal(t, []uint{other}, after)
	})
}

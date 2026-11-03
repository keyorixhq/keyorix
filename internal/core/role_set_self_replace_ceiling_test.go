package core

// role_set_self_replace_ceiling_test.go — #3684: an actor replacing their OWN role set
// with roles they could grant only through a role the replacement removes.
//
// replaceUserRoleSet judged the grant ceiling on the actor's state before commit 1 and
// again in commit 2, after commit 1 had removed the actor's roles.assign role: commit 1
// removed it, commit 2 refused, the actor was left with no role at the project and the
// answer was a PartialMutationError with retry_safe true, whose retry the pre-check
// refused. The fix judges an actor's own replacement on the set commit 1 leaves, before
// commit 1: refused up front, nothing changes. A ceiling refusal that still reaches
// commit 2 (the actor's authority revoked between the commits) is reported with
// retry_safe false. SQLite and PostgreSQL (KEYORIX_TEST_PG_DSN); each case reads the
// database.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReplaceUserRoleSet_SelfReplacementLosingRolesAssign_RefusedUpFront(t *testing.T) {
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		ctx := context.Background()
		scope := Scope{ProjectID: w.f.projectID}
		admin, err := w.f.setup.Storage().GetRoleByName(ctx, "project_admin")
		require.NoError(t, err)

		for _, tc := range []struct {
			name    string
			replace func(c *KeyorixCore, p uint) error
		}{
			{"SetUserRoles", func(c *KeyorixCore, p uint) error {
				return c.SetUserRoles(ctx, p, p, []uint{w.viewerRole.ID}, scope, false)
			}},
			{"SetProjectMemberRole", func(c *KeyorixCore, p uint) error {
				return c.SetProjectMemberRole(ctx, p, w.f.projectID, p, "project_viewer", false)
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				// P is a project admin; a second project admin exists, so the last-admin
				// guard lets P drop their own admin role.
				p := w.newUser("self-p", "project_admin")
				w.newUser("self-q", "project_admin")
				require.Equal(t, []uint{admin.ID}, w.exactRoles(p.ID, scope))
				removedRows, assignedRows := w.eventRows(EventRoleRemoved), w.eventRows(EventRoleAssigned)

				err := tc.replace(w.c, p.ID)
				require.Error(t, err)
				require.NotErrorIs(t, err, ErrMutationPartiallyApplied, "nothing may be applied")
				require.Contains(t, err.Error(), "cannot grant this role", "the same refusal as any other ceiling failure")
				require.Equal(t, []uint{admin.ID}, w.exactRoles(p.ID, scope), "the refused replacement changed P's roles")
				require.Equal(t, removedRows, w.eventRows(EventRoleRemoved))
				require.Equal(t, assignedRows, w.eventRows(EventRoleAssigned))

				// Another admin making the same replacement for P is not affected.
				require.NoError(t, w.c.SetUserRoles(ctx, w.f.adminID, p.ID, []uint{w.viewerRole.ID}, scope, false))
				require.Equal(t, []uint{w.viewerRole.ID}, w.exactRoles(p.ID, scope))
			})
		}

		t.Run("allowed-when-a-group-grant-keeps-roles.assign", func(t *testing.T) {
			// P also holds project_admin at the project through a group: the
			// replacement removes only the direct grant, so P can still grant viewer.
			p := w.newUser("self-g", "project_admin")
			w.newUser("self-g2", "project_admin")
			grp, err := w.f.setup.CreateGroup(ctx, w.f.adminID, &CreateGroupRequest{Name: w.tag("self-grp")})
			require.NoError(t, err)
			require.NoError(t, w.f.setup.Storage().AddUserToGroup(ctx, p.ID, grp.ID, 0))
			require.NoError(t, w.f.setup.Storage().AssignRoleToGroup(ctx, grp.ID, admin.ID, scope))

			require.NoError(t, w.c.SetUserRoles(ctx, p.ID, p.ID, []uint{w.viewerRole.ID}, scope, false))
			require.Equal(t, []uint{w.viewerRole.ID}, w.exactRoles(p.ID, scope))
		})
	})
}

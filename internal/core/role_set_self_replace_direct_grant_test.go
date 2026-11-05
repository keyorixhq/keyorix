package core

// role_set_self_replace_direct_grant_test.go — the positive twin of
// role_set_self_replace_ceiling_test.go for a DIRECT grant (ROLE-CEILING-TAILS-1 note).
//
// The existing allowed case keeps roles.assign through a GROUP grant. Here the actor
// keeps it through a remaining DIRECT grant at the same scope: P holds project_developer
// and project_admin directly, and replaces their own set with project_admin alone. The
// ceiling is judged on the set commit 1 leaves, which still contains project_admin, so
// the replacement must be applied, for both SetUserRoles and SetProjectMemberRole.
// SQLite and PostgreSQL (KEYORIX_TEST_PG_DSN); each case reads the database.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReplaceUserRoleSet_SelfReplacementKeepingRolesAssignDirectly_Allowed(t *testing.T) {
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		ctx := context.Background()
		scope := Scope{ProjectID: w.f.projectID}
		st := w.f.setup.Storage()
		admin, err := st.GetRoleByName(ctx, "project_admin")
		require.NoError(t, err)

		for _, tc := range []struct {
			name    string
			replace func(c *KeyorixCore, p uint) error
		}{
			{"SetUserRoles", func(c *KeyorixCore, p uint) error {
				return c.SetUserRoles(ctx, p, p, []uint{admin.ID}, scope, false)
			}},
			{"SetProjectMemberRole", func(c *KeyorixCore, p uint) error {
				return c.SetProjectMemberRole(ctx, p, w.f.projectID, p, "project_admin", false)
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				// P holds project_admin and project_developer directly; a second project
				// admin exists, so the last-admin guard is not in play.
				p := w.newUser("self-d", "project_admin")
				w.newUser("self-d2", "project_admin")
				require.NoError(t, st.AssignRole(ctx, p.ID, w.devRole.ID, scope))
				require.Equal(t, sortedIDs(admin.ID, w.devRole.ID), w.exactRoles(p.ID, scope))

				require.NoError(t, tc.replace(w.c, p.ID))
				require.Equal(t, []uint{admin.ID}, w.exactRoles(p.ID, scope),
					"the developer role is removed and project_admin, which keeps roles.assign, stays")

				// P can still grant at the scope: the ceiling was not lost.
				q := w.newUser("self-d-q", "project_viewer")
				require.NoError(t, w.c.SetUserRoles(ctx, p.ID, q.ID, []uint{w.devRole.ID}, scope, false))
				require.Equal(t, []uint{w.devRole.ID}, w.exactRoles(q.ID, scope))
			})
		}
	})
}

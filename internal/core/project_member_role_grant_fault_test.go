package core

// project_member_role_grant_fault_test.go — REVOKE-LEFTOVERS-1 item 2 (ATOMIC-OWED-1
// leftover). SetProjectMemberRole removes the member's project roles and grants the
// new one. It used to do that as two independent writes with no compensation, so an
// AssignRole STORAGE error after the removal left the project with no administrator.
// #3488 made it a split mixed request (role_set_replace.go); its tests refuse the
// grant's audit row (set_user_roles_audit_outage_test.go). This one faults the grant
// itself (tx.AssignRole) and reads the database:
//
//   - the sole administrator swapping to another admin-tier role is ONE transaction
//     (swapUserRoleSet): the failed grant rolls the removal back, the member keeps the
//     old role and the project keeps its administrator;
//   - a co-administrator's demotion commits the removal (another administrator still
//     governs the project) and answers a PartialMutationError naming both halves.
//
// SQLite and PostgreSQL (KEYORIX_TEST_PG_DSN).

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestSetProjectMemberRole_GrantStorageFault_NeverStrandsTheProject(t *testing.T) {
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		ctx := context.Background()
		st := w.f.setup.Storage()
		projAdmin, err := st.GetRoleByName(ctx, "project_admin")
		require.NoError(t, err)
		var assignPerm *models.Permission
		perms, err := st.ListPermissions(ctx)
		require.NoError(t, err)
		for _, p := range perms {
			if p.Name == permRolesAssign {
				assignPerm = p
			}
		}
		require.NotNil(t, assignPerm)
		// A second project-admin-tier role (carries roles.assign).
		lead, _, err := w.c.CreateRole(ctx, w.f.adminID, w.tag("spmr-gf-lead"), "lead", []uint{assignPerm.ID})
		require.NoError(t, err)

		// The fault refuses AssignRole for the target user while armed, and counts.
		var (
			target atomic.Uint64
			fired  atomic.Int32
		)
		c := NewKeyorixCore(hooked(w.fs, &storeHooks{
			WrapTx: true,
			AssignRole: func(next storage.Storage, ctx context.Context, userID, roleID uint, s storage.Scope) error {
				if uint64(userID) == target.Load() {
					fired.Add(1)
					return errors.New("injected fault: AssignRole")
				}
				return next.AssignRole(ctx, userID, roleID, s)
			},
		}))
		// held reads the user's roles at exactly s from the database.
		held := func(userID uint, s Scope) []uint {
			t.Helper()
			got, err := st.GetUserRoleIDsExact(ctx, userID, s)
			require.NoError(t, err)
			slices.Sort(got)
			return got
		}
		newProject := func() Scope {
			p, err := w.c.CreateProject(ctx, w.tag("spmr-gf-proj"), "")
			require.NoError(t, err)
			return Scope{ProjectID: p.ID}
		}

		t.Run("sole-admin-swap/nothing-changed", func(t *testing.T) {
			ps := newProject()
			u := w.newUser("spmr-gf-sole", "")
			require.NoError(t, st.AssignRole(ctx, u.ID, projAdmin.ID, ps))
			before := w.fingerprint()

			target.Store(uint64(u.ID))
			fired.Store(0)
			err := c.SetProjectMemberRole(ctx, w.f.adminID, ps.ProjectID, u.ID, lead.Name, false)
			target.Store(0)

			require.Error(t, err)
			require.Positive(t, fired.Load(), "the fault must have fired at the grant")
			require.NotErrorIs(t, err, ErrMutationPartiallyApplied, "the swap is one transaction: nothing applied")
			require.Equal(t, []uint{projAdmin.ID}, held(u.ID, ps), "the member keeps the old role: the project keeps its only administrator")
			require.Equal(t, before, w.fingerprint(), "a failed swap changes nothing, audit rows included")

			// Fault cleared: the same request applies.
			require.NoError(t, c.SetProjectMemberRole(ctx, w.f.adminID, ps.ProjectID, u.ID, lead.Name, false))
			require.Equal(t, []uint{lead.ID}, held(u.ID, ps))
		})

		t.Run("co-admin-demotion/partial-and-says-so", func(t *testing.T) {
			ps := newProject()
			other := w.newUser("spmr-gf-other", "")
			require.NoError(t, st.AssignRole(ctx, other.ID, projAdmin.ID, ps))
			u := w.newUser("spmr-gf-co", "")
			require.NoError(t, st.AssignRole(ctx, u.ID, projAdmin.ID, ps))

			target.Store(uint64(u.ID))
			fired.Store(0)
			err := c.SetProjectMemberRole(ctx, w.f.adminID, ps.ProjectID, u.ID, "project_viewer", false)
			target.Store(0)

			require.Positive(t, fired.Load(), "the fault must have fired at the grant")
			requirePartial(t, err)
			pe, _ := AsPartialMutationError(err)
			require.Contains(t, pe.ClientMessage(), "removal", "the answer names what was applied")
			require.Contains(t, pe.ClientMessage(), "addition", "the answer names what was not applied")
			require.Empty(t, held(u.ID, ps), "the removal committed, the grant did not")
			require.Equal(t, []uint{projAdmin.ID}, held(other.ID, ps), "the project is still governed by the other administrator")

			// Fault cleared: the retry completes the request.
			viewer, err := st.GetRoleByName(ctx, "project_viewer")
			require.NoError(t, err)
			require.NoError(t, c.SetProjectMemberRole(ctx, w.f.adminID, ps.ProjectID, u.ID, "project_viewer", false))
			require.Equal(t, []uint{viewer.ID}, held(u.ID, ps))
		})

		t.Run("sole-admin-demotion/refused-before-any-write", func(t *testing.T) {
			ps := newProject()
			u := w.newUser("spmr-gf-last", "")
			require.NoError(t, st.AssignRole(ctx, u.ID, projAdmin.ID, ps))

			target.Store(uint64(u.ID))
			fired.Store(0)
			err := c.SetProjectMemberRole(ctx, w.f.adminID, ps.ProjectID, u.ID, "project_viewer", false)
			target.Store(0)

			require.ErrorContains(t, err, "last administrator")
			require.Zero(t, fired.Load(), "the guard refuses before the grant is attempted")
			require.Equal(t, []uint{projAdmin.ID}, held(u.ID, ps))
		})

		v, err := w.c.Storage().VerifyAuditChain(ctx, nil)
		require.NoError(t, err)
		require.True(t, v.Valid, v.Reason)
	})
}

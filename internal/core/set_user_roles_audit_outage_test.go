package core

// set_user_roles_audit_outage_test.go — #3488: SetUserRoles during an audit outage.
//
// A role-set replacement that removes AND adds is a mixed request
// (INV-CORE-mixed-request-split): the removals commit first in one transaction, their
// role.removed rows owed (never blocked by the audit log), then the additions in one
// fail-closed transaction. Before the fix the removals ran one by one, the additions
// failed closed on role.assigned, and the "revert" re-granted the removed roles through
// AssignUserRole, which failed closed too: the user lost a role and the error said
// "nothing was changed".
//
// The fault refuses LogAuditEvent for role.assigned rows only (the shape #3488 was
// reproduced with), or every row (a total outage). Each case reads the database: after a
// failed call the role set is the set before, or exactly the set before minus the
// removals, and the error says which. SQLite and PostgreSQL (KEYORIX_TEST_PG_DSN).

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

// eventAuditOutage refuses audit appends while down is set: only rows of eventType, or
// every row when eventType is "".
type eventAuditOutage struct {
	down      atomic.Bool
	eventType string
}

func (o *eventAuditOutage) wrap(inner storage.Storage) storage.Storage {
	return hooked(inner, &storeHooks{
		WrapTx: true,
		LogAuditEvent: func(next storage.Storage, ctx context.Context, e *models.AuditEvent) error {
			if o.down.Load() && (o.eventType == "" || e.EventType == o.eventType) {
				return errors.New("audit log refuses writes")
			}
			return next.LogAuditEvent(ctx, e)
		},
	})
}

func (w *satWorld) exactRoles(userID uint, scope Scope) []uint {
	w.t.Helper()
	got, err := w.f.setup.Storage().GetUserRoleIDsExact(context.Background(), userID, scope)
	require.NoError(w.t, err)
	slices.Sort(got)
	return got
}

func sortedIDs(ids ...uint) []uint {
	out := slices.Clone(ids)
	slices.Sort(out)
	return out
}

func TestSetUserRoles_AuditOutage_NeverLosesARole(t *testing.T) {
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		ctx := context.Background()
		scope := Scope{ProjectID: w.f.projectID}
		admin, err := w.f.setup.Storage().GetRoleByName(ctx, "project_admin")
		require.NoError(t, err)
		viewer, dev := w.viewerRole.ID, w.devRole.ID

		// A user holding viewer + developer at the project.
		newTarget := func() *models.User {
			u := w.newUser("sur-target", "project_viewer")
			require.NoError(t, w.f.setup.Storage().AssignRole(ctx, u.ID, dev, scope))
			return u
		}

		for _, tc := range []struct {
			name      string
			eventType string // refused event type ("" = every row)
			want      []uint
			// after is the role set the call must leave; partial: the error must be a
			// PartialMutationError (the removals applied, the additions not).
			after   []uint
			partial bool
			ok      bool  // the call must succeed
			owed    int64 // role.removed rows queued (pending) by the call
		}{
			// #3488's reproduction: keep viewer, drop developer, add admin.
			{name: "mixed/role.assigned-refused", eventType: EventRoleAssigned, want: []uint{viewer, admin.ID},
				after: []uint{viewer}, partial: true},
			{name: "mixed/total-outage", want: []uint{viewer, admin.ID},
				after: []uint{viewer}, partial: true, owed: 1},
			{name: "widen-only/role.assigned-refused", eventType: EventRoleAssigned, want: []uint{viewer, dev, admin.ID},
				after: []uint{viewer, dev}},
			{name: "narrow-only/total-outage", want: []uint{viewer},
				after: []uint{viewer}, ok: true, owed: 1},
			{name: "narrow-to-none/total-outage", want: []uint{},
				after: []uint{}, ok: true, owed: 2},
		} {
			t.Run(tc.name, func(t *testing.T) {
				u := newTarget()
				before := w.exactRoles(u.ID, scope)
				require.Equal(t, sortedIDs(viewer, dev), before)
				pending, removedRows, assignedRows := w.pendingTotal(), w.eventRows(EventRoleRemoved), w.eventRows(EventRoleAssigned)
				o := &eventAuditOutage{eventType: tc.eventType}
				c := NewKeyorixCore(o.wrap(w.fs))

				o.down.Store(true)
				err := c.SetUserRoles(ctx, w.f.adminID, u.ID, tc.want, scope, false)
				o.down.Store(false)

				got := w.exactRoles(u.ID, scope)
				require.Equal(t, sortedIDs(tc.after...), got, "the role set after the call (before: %v)", before)
				require.Equal(t, assignedRows, w.eventRows(EventRoleAssigned), "no role.assigned row may exist for a refused grant")
				switch {
				case tc.ok:
					require.NoError(t, err, "a narrowing must never be blocked by the audit log")
				case tc.partial:
					requirePartial(t, err)
					require.ErrorIs(t, err, ErrMutationAuditUnavailable)
					pe, _ := AsPartialMutationError(err)
					require.Contains(t, pe.ClientMessage(), "removal", "the answer names what was applied")
					require.Contains(t, pe.ClientMessage(), "addition", "the answer names what was not applied")
				default:
					require.ErrorIs(t, err, ErrMutationAuditUnavailable)
					require.NotErrorIs(t, err, ErrMutationPartiallyApplied, "nothing was removed, so nothing was applied")
					require.Equal(t, before, got, "a refused widening changed the role set")
				}
				// Every removal that committed has its row: written, or owed.
				removed := int64(len(before) - len(got))
				require.Equal(t, removed, w.eventRows(EventRoleRemoved)-removedRows+(w.pendingTotal()-pending),
					"each committed removal has exactly one role.removed row, written or queued")
				require.Equal(t, pending+tc.owed, w.pendingTotal(), "the removals' rows queued while the log is down")

				if tc.partial {
					// The retry of the same request, audit up, completes it.
					require.NoError(t, c.SetUserRoles(ctx, w.f.adminID, u.ID, tc.want, scope, false))
					require.Equal(t, sortedIDs(tc.want...), w.exactRoles(u.ID, scope))
				}
			})
		}

		// A failure inside the removals' own transaction leaves the ORIGINAL set: the
		// removals are one transaction, never some of them.
		t.Run("narrowing-fails-midway/original-set", func(t *testing.T) {
			u := newTarget()
			before := w.exactRoles(u.ID, scope)
			var n atomic.Int32
			c := NewKeyorixCore(hooked(w.fs, &storeHooks{
				WrapTx: true,
				RemoveRole: func(next storage.Storage, ctx context.Context, userID, roleID uint, s storage.Scope) error {
					if userID == u.ID && n.Add(1) == 2 {
						return errors.New("injected fault: RemoveRole")
					}
					return next.RemoveRole(ctx, userID, roleID, s)
				},
			}))
			err := c.SetUserRoles(ctx, w.f.adminID, u.ID, []uint{admin.ID}, scope, false)
			require.Error(t, err)
			require.NotErrorIs(t, err, ErrMutationPartiallyApplied)
			require.Equal(t, int32(2), n.Load(), "the fault must have fired on the second removal")
			require.Equal(t, before, w.exactRoles(u.ID, scope), "a failed narrowing must leave the original set")
		})

		v, err := w.c.Storage().VerifyAuditChain(ctx, nil)
		require.NoError(t, err)
		require.True(t, v.Valid, v.Reason)
	})
}

// TestSetUserRoles_RefusedAdditionChangesNothing: an addition the separation-of-duties
// gate refuses is refused BEFORE any removal commits, judged on the role set the
// removals leave (a replacement that swaps a conflicting role out is allowed).
func TestSetUserRoles_RefusedAdditionChangesNothing(t *testing.T) {
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		ctx := context.Background()
		st := w.f.setup.Storage()
		pa, err := st.CreatePermission(ctx, &models.Permission{Name: "sur.sod.a", Description: "sur"})
		require.NoError(t, err)
		pb, err := st.CreatePermission(ctx, &models.Permission{Name: "sur.sod.b", Description: "sur"})
		require.NoError(t, err)
		_, err = w.c.CreateSoDPolicy(ctx, w.f.adminID, "sur-a-vs-b", "", pa.Name, pb.Name)
		require.NoError(t, err)
		roleA, _, err := w.c.CreateRole(ctx, w.f.adminID, "sur-role-a", "a", []uint{pa.ID})
		require.NoError(t, err)
		roleB, _, err := w.c.CreateRole(ctx, w.f.adminID, "sur-role-b", "b", []uint{pb.ID})
		require.NoError(t, err)
		scope := Scope{ProjectID: w.f.projectID}
		envScope := Scope{ProjectID: w.f.projectID, EnvironmentID: w.f.envID}

		t.Run("swap-out-the-conflict/allowed", func(t *testing.T) {
			u := w.newUser("sur-sod-swap", "")
			require.NoError(t, st.AssignRole(ctx, u.ID, roleA.ID, scope))
			require.NoError(t, w.c.SetUserRoles(ctx, w.f.adminID, u.ID, []uint{roleB.ID}, scope, false))
			require.Equal(t, []uint{roleB.ID}, w.exactRoles(u.ID, scope))
		})
		t.Run("conflict-survives-elsewhere/refused-nothing-changed", func(t *testing.T) {
			u := w.newUser("sur-sod-keep", "")
			require.NoError(t, st.AssignRole(ctx, u.ID, roleA.ID, scope))
			require.NoError(t, st.AssignRole(ctx, u.ID, roleA.ID, envScope)) // a.* still held after the swap
			before := w.fingerprint()
			err := w.c.SetUserRoles(ctx, w.f.adminID, u.ID, []uint{roleB.ID}, scope, false)
			require.ErrorContains(t, err, "separation-of-duties")
			require.NotErrorIs(t, err, ErrMutationPartiallyApplied, "a refused request applies nothing")
			require.Equal(t, []uint{roleA.ID}, w.exactRoles(u.ID, scope), "the removal must not commit when the addition is refused")
			require.Equal(t, before, w.fingerprint())
		})
		t.Run("two-additions-conflict-together/refused", func(t *testing.T) {
			u := w.newUser("sur-sod-pair", "project_viewer")
			before := w.fingerprint()
			err := w.c.SetUserRoles(ctx, w.f.adminID, u.ID, []uint{roleA.ID, roleB.ID}, scope, false)
			require.ErrorContains(t, err, "separation-of-duties")
			require.Equal(t, []uint{w.viewerRole.ID}, w.exactRoles(u.ID, scope))
			require.Equal(t, before, w.fingerprint())
		})
	})
}

// TestSetProjectMemberRole_AuditOutage_NeverStrandsOrLies (#3488's sibling): a member
// role change removes the member's other project roles and grants the new one. The
// removals used to commit one by one (owed) and the grant then failed closed with
// "nothing was changed": the member lost their roles silently, and an admin-to-admin
// swap of the project's only administrator left the project with none.
func TestSetProjectMemberRole_AuditOutage_NeverStrandsOrLies(t *testing.T) {
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		ctx := context.Background()
		st := w.f.setup.Storage()
		scope := Scope{ProjectID: w.f.projectID}
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
		lead, _, err := w.c.CreateRole(ctx, w.f.adminID, "spmr-lead", "lead", []uint{assignPerm.ID})
		require.NoError(t, err)

		o := &eventAuditOutage{eventType: EventRoleAssigned}
		c := NewKeyorixCore(o.wrap(w.fs))

		t.Run("mixed/role.assigned-refused/says-which-half", func(t *testing.T) {
			u := w.newUser("spmr-member", "project_viewer")
			require.NoError(t, st.AssignRole(ctx, u.ID, w.devRole.ID, scope))
			o.down.Store(true)
			err := c.SetProjectMemberRole(ctx, w.f.adminID, w.f.projectID, u.ID, "project_admin", false)
			o.down.Store(false)
			requirePartial(t, err)
			require.ErrorIs(t, err, ErrMutationAuditUnavailable)
			require.Empty(t, w.exactRoles(u.ID, scope), "the removals applied, the grant did not")
			require.NoError(t, c.SetProjectMemberRole(ctx, w.f.adminID, w.f.projectID, u.ID, "project_admin", false), "retry")
			require.Equal(t, []uint{projAdmin.ID}, w.exactRoles(u.ID, scope))
		})

		t.Run("sole-admin-swap/role.assigned-refused/nothing-changed", func(t *testing.T) {
			p, err := w.c.CreateProject(ctx, w.tag("spmr-proj"), "")
			require.NoError(t, err)
			ps := Scope{ProjectID: p.ID}
			u := w.newUser("spmr-sole", "")
			require.NoError(t, st.AssignRole(ctx, u.ID, projAdmin.ID, ps))
			before := w.fingerprint()
			o.down.Store(true)
			err = c.SetProjectMemberRole(ctx, w.f.adminID, p.ID, u.ID, lead.Name, false)
			o.down.Store(false)
			require.ErrorIs(t, err, ErrMutationAuditUnavailable)
			require.NotErrorIs(t, err, ErrMutationPartiallyApplied, "the swap is one transaction: nothing applied")
			require.Equal(t, []uint{projAdmin.ID}, w.exactRoles(u.ID, ps), "the project must keep its only administrator")
			require.Equal(t, before, w.fingerprint())

			// Audit up: the swap applies, in one transaction, both rows written.
			removed, assigned := w.eventRows(EventRoleRemoved), w.eventRows(EventRoleAssigned)
			require.NoError(t, c.SetProjectMemberRole(ctx, w.f.adminID, p.ID, u.ID, lead.Name, false))
			require.Equal(t, []uint{lead.ID}, w.exactRoles(u.ID, ps))
			require.Equal(t, removed+1, w.eventRows(EventRoleRemoved))
			require.Equal(t, assigned+1, w.eventRows(EventRoleAssigned))
		})

		t.Run("sole-admin-demotion/refused", func(t *testing.T) {
			p, err := w.c.CreateProject(ctx, w.tag("spmr-proj"), "")
			require.NoError(t, err)
			ps := Scope{ProjectID: p.ID}
			u := w.newUser("spmr-demote", "")
			require.NoError(t, st.AssignRole(ctx, u.ID, projAdmin.ID, ps))
			err = c.SetProjectMemberRole(ctx, w.f.adminID, p.ID, u.ID, "project_viewer", false)
			require.ErrorContains(t, err, "last administrator")
			require.Equal(t, []uint{projAdmin.ID}, w.exactRoles(u.ID, ps))
		})

		v, err := w.c.Storage().VerifyAuditChain(ctx, nil)
		require.NoError(t, err)
		require.True(t, v.Valid, v.Reason)
	})
}

// TestMembershipTransition_AuditOutage_NoReGrantNoLostRole clears #3488's other
// compensating sequence: TransitionMembership (and the open-mode invite) commits the
// membership row, then grants or removes the role, and on a failed side effect puts
// the ROW back. The revert is a plain conditional row write (no audit dependency) and
// nothing is ever re-granted: a refused grant leaves the role set unchanged and the
// row in its previous state; a revocation is owed and never blocked.
func TestMembershipTransition_AuditOutage_NoReGrantNoLostRole(t *testing.T) {
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		ctx := context.Background()
		scope := Scope{ProjectID: w.f.projectID}
		o := &eventAuditOutage{eventType: EventRoleAssigned}
		c := NewKeyorixCore(o.wrap(w.fs))
		provisioned := func(name string) (*models.User, *models.ProjectMembership) {
			u := w.newUser(name, "")
			m, err := w.c.InviteMember(ctx, w.f.projectID, u.ID, "project_viewer", w.f.adminID, 0, false)
			require.NoError(t, err)
			for _, to := range []string{MembershipIdentityVerified, MembershipProvisioned} {
				m, err = w.c.TransitionMembership(ctx, w.f.projectID, m.ID, to, w.f.adminID, false)
				require.NoError(t, err)
			}
			return u, m
		}

		t.Run("activation/role.assigned-refused/row-back-no-role", func(t *testing.T) {
			u, m := provisioned("mt-activate")
			o.down.Store(true)
			_, err := c.TransitionMembership(ctx, w.f.projectID, m.ID, MembershipActive, w.f.adminID, false)
			o.down.Store(false)
			require.ErrorIs(t, err, ErrMutationAuditUnavailable)
			got, gerr := w.f.setup.Storage().GetProjectMembership(ctx, m.ID)
			require.NoError(t, gerr)
			require.Equal(t, MembershipProvisioned, got.State, "the row is back in its previous state")
			require.Empty(t, w.exactRoles(u.ID, scope), "the grant was refused, nothing granted")
			// Audit up: the retry activates.
			_, err = c.TransitionMembership(ctx, w.f.projectID, m.ID, MembershipActive, w.f.adminID, false)
			require.NoError(t, err)
			require.Len(t, w.exactRoles(u.ID, scope), 1)
		})

		t.Run("revocation/total-outage/owed-never-blocked", func(t *testing.T) {
			u, m := provisioned("mt-revoke")
			_, err := w.c.TransitionMembership(ctx, w.f.projectID, m.ID, MembershipActive, w.f.adminID, false)
			require.NoError(t, err)
			total := &eventAuditOutage{}
			tc := NewKeyorixCore(total.wrap(w.fs))
			pending := w.pendingTotal()
			total.down.Store(true)
			_, err = tc.TransitionMembership(ctx, w.f.projectID, m.ID, MembershipRevoked, w.f.adminID, false)
			total.down.Store(false)
			require.NoError(t, err, "a revocation must never be blocked by the audit log")
			require.Empty(t, w.exactRoles(u.ID, scope))
			require.Greater(t, w.pendingTotal(), pending, "the role.removed row is owed")
		})

		t.Run("open-mode-invite/role.assigned-refused/revoked-no-role", func(t *testing.T) {
			u := w.newUser("mt-open", "")
			c.SetMembershipValidationMode(ValidationModeOpen)
			defer c.SetMembershipValidationMode(ValidationModeAllowlist)
			o.down.Store(true)
			_, err := c.InviteMember(ctx, w.f.projectID, u.ID, "project_viewer", w.f.adminID, 0, false)
			o.down.Store(false)
			require.ErrorIs(t, err, ErrMutationAuditUnavailable)
			require.Empty(t, w.exactRoles(u.ID, scope))
			ms, lerr := w.f.setup.Storage().ListProjectMemberships(ctx, w.f.projectID)
			require.NoError(t, lerr)
			found := false
			for _, m := range ms {
				if m.UserID == u.ID {
					found = true
					require.Equal(t, MembershipRevoked, m.State, "the never-activated row is revoked, not left active")
				}
			}
			require.True(t, found, "the invite created its membership row")
		})
	})
}

// TestAccessRequestApproval_AuditOutage_NothingApplied clears finalizeAccessRequestApproval
// (#3488's list): the grant, the approval record and the request state are one
// fail-closed transaction (no compensating re-grant), so a refused role.assigned row
// leaves the request pending, no role and no approval, and the error says so truthfully.
func TestAccessRequestApproval_AuditOutage_NothingApplied(t *testing.T) {
	smaBackends(t, func(t *testing.T, sw *smaWorld) {
		w := newSATWorld(t, sw.f)
		ctx := context.Background()
		st := w.f.setup.Storage()
		u := w.newUser("ar-requester", "")
		req, err := st.CreateAccessRequest(ctx, &models.AccessRequest{
			ProjectID: w.f.projectID, UserID: u.ID, SuggestedRole: "project_viewer", State: AccessRequestPending,
		})
		require.NoError(t, err)
		o := &eventAuditOutage{eventType: EventRoleAssigned}
		c := NewKeyorixCore(o.wrap(w.fs))
		before := w.fingerprint()
		o.down.Store(true)
		_, err = c.ApproveAccessRequestWithExpiry(ctx, w.f.projectID, req.ID, w.f.adminID, 0, "", 0)
		o.down.Store(false)
		require.ErrorIs(t, err, ErrMutationAuditUnavailable)
		require.Equal(t, before, w.fingerprint(), "nothing applied")
		got, err := st.GetAccessRequest(ctx, req.ID)
		require.NoError(t, err)
		require.Equal(t, AccessRequestPending, got.State)
		require.Empty(t, w.exactRoles(u.ID, Scope{ProjectID: w.f.projectID}))
	})
}

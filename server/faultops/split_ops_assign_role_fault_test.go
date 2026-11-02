// split_ops_assign_role_fault_test.go -- WORDING-FAULTOPS-TAILS-1 item 3 (REVOKE-LEFTOVERS-1
// leftover). The owed-audit sweep (owed_audit_split_ops_test.go) refuses the audit row of
// the split mixed-request ops. This file faults the grant itself: AssignRole returns a PLAIN
// storage error (not an audit refusal) after the narrowing commit, on every op that
// removes a principal's role and then grants another through the real HTTP stack:
//
//   - SetUserRoles       PUT /api/v1/users/{id}/roles
//   - SetProjectMemberRole PUT /api/v1/projects/{id}/members/{userId}
//   - the membership transition that grants the role on activation
//     PUT /api/v1/projects/{id}/memberships/{membershipId} {"action":"activate"}
//
// The assertions read the database (the effect), not only the status code:
//
//   - a project's only administrator is never left without the administrator role: the
//     swap to another admin-tier role is one transaction (nothing changes), and a plain
//     replacement that would strand the project is refused before any write;
//   - when the narrowing stands and the grant failed (a viewer given a developer role, a
//     co-administrator demoted), the answer is the partial-mutation 503 naming BOTH
//     halves, and the project is still governed by another administrator;
//   - a membership whose activation grant failed is put back to its previous state, not
//     left "active" with no role.
//
// The partial body is decoded from literals, not from core constants, so the test also
// compiles against a tree from before the split (#3488) and can show red there.
package faultops

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// assignFaultPartial is the 503 body of a request whose first half was applied.
type assignFaultPartial struct {
	Error   string         `json:"error"`
	Details map[string]any `json:"details"`
}

func decodeAssignFaultPartial(st int, body []byte) (assignFaultPartial, bool) {
	var p assignFaultPartial
	if st != http.StatusServiceUnavailable || json.Unmarshal(body, &p) != nil || p.Error != "MutationPartiallyApplied" {
		return p, false
	}
	return p, true
}

// assignFaultHeld reads the roles userID holds at exactly project projectID (env 0) from the database.
func assignFaultHeld(t *testing.T, w *faultWorld, userID, projectID uint) []uint {
	t.Helper()
	var rows []models.UserRole
	require.NoError(t, w.db.Where("user_id = ? AND project_id = ? AND environment_id = 0", userID, projectID).Find(&rows).Error)
	ids := []uint{}
	for _, r := range rows {
		ids = append(ids, r.RoleID)
	}
	slices.Sort(ids)
	return ids
}

// assignFaultHolders returns the users holding any of adminRoles at the project, sorted.
func assignFaultHolders(t *testing.T, w *faultWorld, projectID uint, adminRoles ...uint) []uint {
	t.Helper()
	var rows []models.UserRole
	require.NoError(t, w.db.Where("project_id = ? AND environment_id = 0 AND role_id IN ?", projectID, adminRoles).Find(&rows).Error)
	ids := []uint{}
	for _, r := range rows {
		ids = append(ids, r.UserID)
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

func TestSplitOps_AssignRoleStorageFault_NeverStrandsAPrincipal(t *testing.T) {
	const projectID = 1
	ctx := context.Background()

	type fixture struct {
		w                                  *faultWorld
		projAdmin, lead, viewer, developer uint
		adminRoles                         []uint
	}
	roleID := func(t *testing.T, w *faultWorld, name string) uint {
		t.Helper()
		var r models.Role
		require.NoError(t, w.db.Where("name = ?", name).First(&r).Error)
		return r.ID
	}
	newFixture := func(t *testing.T) *fixture {
		t.Helper()
		w := newFaultWorld(t, nil)
		leadID, err := createRoleWithPermissionsForFuzz(ctx, w, "assignfault-lead", "roles.assign")
		require.NoError(t, err)
		f := &fixture{
			w: w, projAdmin: roleID(t, w, "project_admin"), lead: leadID,
			viewer: roleID(t, w, "project_viewer"), developer: roleID(t, w, "project_developer"),
		}
		f.adminRoles = []uint{f.projAdmin, f.lead}
		return f
	}
	grant := func(t *testing.T, f *fixture, userID, role uint) {
		t.Helper()
		require.NoError(t, f.w.db.Create(&models.UserRole{UserID: userID, RoleID: role, ProjectID: projectID}).Error)
	}
	newUser := func(t *testing.T, f *fixture, name string, role uint) uint {
		t.Helper()
		id, err := createUserForFuzz(ctx, f.w, name)
		require.NoError(t, err)
		if role != 0 {
			grant(t, f, id, role)
		}
		return id
	}
	putUserRoles := func(f *fixture, userID uint, roles ...uint) (int, []byte) {
		st, body, err := httpJSON(ctx, f.w, http.MethodPut, fmt.Sprintf("/api/v1/users/%d/roles", userID), map[string]any{
			"role_ids": roles, "project_id": projectID, "environment_id": 0,
		})
		require.NoError(t, err)
		return st, body
	}
	putMember := func(f *fixture, userID uint, role string) (int, []byte) {
		st, body, err := httpJSON(ctx, f.w, http.MethodPut, fmt.Sprintf("/api/v1/projects/%d/members/%d", projectID, userID), map[string]any{"role": role})
		require.NoError(t, err)
		return st, body
	}
	// faulted arms AssignRole (plain storage error, first call after arming) around send.
	faulted := func(t *testing.T, f *fixture, send func() (int, []byte)) (int, []byte) {
		t.Helper()
		f.w.faulty.Arm(&faultstorage.FaultSpec{Method: "AssignRole", NthCall: 1, Kind: faultstorage.KindError, Err: errFuzzInjected})
		st, body := send()
		fired := f.w.faulty.Fired()
		f.w.faulty.Arm(nil)
		drainAllBackgroundGoroutines()
		require.True(t, fired, "the fault must have fired at the grant (HTTP %d: %s)", st, body)
		return st, body
	}
	requirePartialNamesBothHalves := func(t *testing.T, st int, body []byte, removed, notAdded uint) {
		t.Helper()
		p, ok := decodeAssignFaultPartial(st, body)
		require.True(t, ok, "a plain AssignRole fault after the narrowing must answer the partial-mutation 503, got HTTP %d: %s", st, body)
		require.Equal(t, "mutation_partially_applied", fmt.Sprint(p.Details["code"]))
		require.Equal(t, "true", fmt.Sprint(p.Details["revocation_applied"]), "the answer must say the narrowing stands")
		require.Equal(t, "false", fmt.Sprint(p.Details["remainder_applied"]), "the answer must say the grant did not apply")
		require.Equal(t, "true", fmt.Sprint(p.Details["retry_safe"]))
		require.Contains(t, fmt.Sprint(p.Details["applied"]), fmt.Sprint(removed), "the applied half names the removed role")
		require.Contains(t, fmt.Sprint(p.Details["not_applied"]), fmt.Sprint(notAdded), "the unapplied half names the role not granted")
	}

	t.Run("SetUserRoles/viewer-to-developer/partial-names-both-halves", func(t *testing.T) {
		f := newFixture(t)
		u := newUser(t, f, "assignfault-sur", f.viewer)
		st, body := faulted(t, f, func() (int, []byte) { return putUserRoles(f, u, f.developer) })
		requirePartialNamesBothHalves(t, st, body, f.viewer, f.developer)
		require.Empty(t, assignFaultHeld(t, f.w, u, projectID), "the narrowing committed, the grant did not")
		// Fault cleared: the retry the answer promises is safe and completes the request.
		st, body = putUserRoles(f, u, f.developer)
		require.Equal(t, http.StatusOK, st, string(body))
		require.Equal(t, []uint{f.developer}, assignFaultHeld(t, f.w, u, projectID))
	})

	t.Run("SetProjectMemberRole/viewer-to-developer/partial-names-both-halves", func(t *testing.T) {
		f := newFixture(t)
		u := newUser(t, f, "assignfault-spmr", f.viewer)
		st, body := faulted(t, f, func() (int, []byte) { return putMember(f, u, "project_developer") })
		requirePartialNamesBothHalves(t, st, body, f.viewer, f.developer)
		require.Empty(t, assignFaultHeld(t, f.w, u, projectID))
		st, body = putMember(f, u, "project_developer")
		require.Equal(t, http.StatusOK, st, string(body))
		require.Equal(t, []uint{f.developer}, assignFaultHeld(t, f.w, u, projectID))
	})

	t.Run("SetProjectMemberRole/sole-admin-swap/keeps-role-and-project-keeps-its-administrator", func(t *testing.T) {
		f := newFixture(t)
		u := newUser(t, f, "assignfault-sole", f.projAdmin)
		require.Equal(t, []uint{u}, assignFaultHolders(t, f.w, projectID, f.adminRoles...), "precondition: u is the project's only administrator")
		st, body := faulted(t, f, func() (int, []byte) { return putMember(f, u, "assignfault-lead") })
		require.GreaterOrEqual(t, st, 400, string(body))
		_, partial := decodeAssignFaultPartial(st, body)
		require.False(t, partial, "the swap is one transaction: nothing was applied, so the answer must not claim a partial apply")
		require.Equal(t, []uint{f.projAdmin}, assignFaultHeld(t, f.w, u, projectID), "the member keeps the old role")
		require.Equal(t, []uint{u}, assignFaultHolders(t, f.w, projectID, f.adminRoles...), "the project keeps its administrator")
		st, body = putMember(f, u, "assignfault-lead")
		require.Equal(t, http.StatusOK, st, string(body))
		require.Equal(t, []uint{f.lead}, assignFaultHeld(t, f.w, u, projectID))
	})

	t.Run("SetProjectMemberRole/co-admin-demotion/partial-and-project-still-governed", func(t *testing.T) {
		f := newFixture(t)
		other := newUser(t, f, "assignfault-other", f.projAdmin)
		u := newUser(t, f, "assignfault-co", f.projAdmin)
		st, body := faulted(t, f, func() (int, []byte) { return putMember(f, u, "project_viewer") })
		requirePartialNamesBothHalves(t, st, body, f.projAdmin, f.viewer)
		require.Empty(t, assignFaultHeld(t, f.w, u, projectID))
		require.Equal(t, []uint{other}, assignFaultHolders(t, f.w, projectID, f.adminRoles...), "the other administrator still governs the project")
	})

	t.Run("SetUserRoles/sole-admin-replace/refused-before-any-write", func(t *testing.T) {
		f := newFixture(t)
		u := newUser(t, f, "assignfault-sur-sole", f.projAdmin)
		require.Equal(t, []uint{u}, assignFaultHolders(t, f.w, projectID, f.adminRoles...), "precondition: u is the project's only administrator")
		// SetUserRoles has no atomic swap: the removal alone would strand the project, so
		// it is refused before the grant is attempted and the fault never fires.
		f.w.faulty.Arm(&faultstorage.FaultSpec{Method: "AssignRole", NthCall: 1, Kind: faultstorage.KindError, Err: errFuzzInjected})
		st, body := putUserRoles(f, u, f.lead)
		f.w.faulty.Arm(nil)
		drainAllBackgroundGoroutines()
		require.GreaterOrEqual(t, st, 400, string(body))
		_, partial := decodeAssignFaultPartial(st, body)
		require.False(t, partial, string(body))
		require.Equal(t, []uint{f.projAdmin}, assignFaultHeld(t, f.w, u, projectID))
		require.Equal(t, []uint{u}, assignFaultHolders(t, f.w, projectID, f.adminRoles...))
	})

	t.Run("TransitionMembership/activate/grant-fault-reverts-the-membership", func(t *testing.T) {
		f := newFixture(t)
		u := newUser(t, f, "assignfault-member", 0)
		st, body, err := httpJSON(ctx, f.w, http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/memberships", projectID), map[string]any{"user_id": u, "role": "viewer"})
		require.NoError(t, err)
		require.Equal(t, 2, st/100, string(body))
		var inv struct {
			Data struct {
				Membership struct {
					ID uint `json:"id"`
				} `json:"membership"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(body, &inv))
		mid := inv.Data.Membership.ID
		require.NotZero(t, mid)
		transition := func(action string) (int, []byte) {
			st, body, err := httpJSON(ctx, f.w, http.MethodPut, fmt.Sprintf("/api/v1/projects/%d/memberships/%d", projectID, mid), map[string]any{"action": action})
			require.NoError(t, err)
			return st, body
		}
		for _, step := range []string{"verify", "provision"} {
			st, body := transition(step)
			require.Equal(t, 2, st/100, "%s: %s", step, body)
		}
		stateOf := func() string {
			var m models.ProjectMembership
			require.NoError(t, f.w.db.First(&m, mid).Error)
			return m.State
		}
		require.Equal(t, "provisioned", stateOf())

		st, body = faulted(t, f, func() (int, []byte) { return transition("activate") })
		require.GreaterOrEqual(t, st, 400, string(body))
		require.Equal(t, "provisioned", stateOf(), "a membership whose grant failed is put back, not left active without a role")
		require.Empty(t, assignFaultHeld(t, f.w, u, projectID), "no role was granted")

		// Fault cleared: the activation is retriable and grants the role.
		st, body = transition("activate")
		require.Equal(t, 2, st/100, string(body))
		require.Equal(t, "active", stateOf())
		require.NotEmpty(t, assignFaultHeld(t, f.w, u, projectID))
	})
}

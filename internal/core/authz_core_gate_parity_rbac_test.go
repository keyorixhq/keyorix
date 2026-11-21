// authz_core_gate_parity_rbac_test.go — #4161 item 2: the GLOBAL route gates of the
// role, user and group operations, decided in core. See
// authz_core_gate_parity_test.go for the fixture and the runner.
package core

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestCoreGateParity_RolesUsersGroups: denied is a project_admin of project A —
// roles.assign and users.read AT A, which is exactly what let core allow these
// before — or, where an older ceiling already refuses that principal, a
// gate-isolating global holder (see authz_core_gate_parity_test.go); admitted is
// the global admin.
func TestCoreGateParity_RolesUsersGroups(t *testing.T) {
	t.Parallel()
	runGateCases(t, func(w *parityWorld) []gateCase {
		ctx, t := w.ctx, w.t
		permAdder, permAdderRole := w.globalHolder("parity-gate-perm-adder", "secrets.read")
		creator, creatorRole := w.globalHolder("parity-gate-creator", permSystemRead, permUsersRead)
		assigner, assignerRole := w.globalHolder("parity-gate-assigner", permSystemRead, permUsersRead)
		padminRole, err := w.st.GetRoleByName(ctx, "project_admin")
		require.NoError(t, err)
		require.NoError(t, w.st.AssignRole(ctx, assigner, padminRole.ID, Scope{ProjectID: w.projA}))
		return []gateCase{
			{op: "role.update", deniedBy: w.padminA, allowedBy: w.admin, run: func(a string) func(uint) error {
				r := w.customRole("parity-upd-" + a)
				return func(actor uint) error {
					_, _, err := w.c.UpdateRole(ctx, actor, &models.Role{ID: r.ID, Name: r.Name, Description: "updated"}, nil)
					return err
				}
			}},
			{op: "role.delete", deniedBy: w.padminA, allowedBy: w.admin, run: func(a string) func(uint) error {
				r := w.customRole("parity-del-" + a)
				return func(actor uint) error { return w.c.DeleteRole(ctx, actor, r.ID) }
			}},
			// Gate-isolating: secrets.read held globally passes the #169
			// self-permission rule that already refused padminA; roles.read and
			// roles.write are all it lacks.
			{op: "role.perm.add", deniedBy: permAdder, allowedBy: w.admin, run: func(a string) func(uint) error {
				r := w.customRole("parity-perm-" + a)
				pid := w.permissionID("secrets.read")
				return func(actor uint) error { return w.c.AssignPermissionToRole(ctx, actor, r.ID, pid, false) }
			}, grantGate: func() { w.grantToRole(permAdderRole, permRolesRead, "roles.write") }},
			{op: "group.restore", deniedBy: w.padminA, allowedBy: w.admin, run: func(a string) func(uint) error {
				g := w.group("parity-restore-" + a)
				require.NoError(t, w.st.DeleteGroup(ctx, g.ID))
				return func(actor uint) error { _, err := w.c.RestoreGroup(ctx, actor, g.ID); return err }
			}},
			{op: "group.role.assign", deniedBy: w.padminA, allowedBy: w.admin, run: func(a string) func(uint) error {
				g := w.group("parity-grole-" + a)
				return func(actor uint) error {
					return w.c.AssignRoleToGroup(ctx, actor, g.ID, w.viewerRoleID, Scope{ProjectID: w.projA}, false)
				}
			}},
			{op: "group.member.add", deniedBy: w.padminA, allowedBy: w.admin, run: func(a string) func(uint) error {
				g := w.group("parity-gmember-" + a)
				return func(actor uint) error { return w.c.AddUserToGroup(ctx, actor, false, w.viewerA, g.ID, w.projA) }
			}},
			// user.roles.set (SetUserRoles) is NOT gated here: core keeps its finer
			// per-scope granter ceiling (replaceUserRoleSet) and the differential
			// classifies the op coreGateExcluded; see rbac_management.go.
			// Gate-isolating: the system_viewer baseline (system.read) held
			// globally passes the baseline-role ceiling that already refused
			// padminA; users.write is all it lacks.
			{op: "user.create", deniedBy: creator, allowedBy: w.admin, run: func(a string) func(uint) error {
				return func(actor uint) error {
					_, err := w.c.CreateUserAudited(ctx, w.newUser("plain-"+a), actor, false)
					return err
				}
			}, grantGate: func() { w.grantToRole(creatorRole, permUsersWrite) }},
			// The same, plus project_admin at A for the per-grant ceiling of the
			// project_viewer assignment.
			{op: "user.create.assign", deniedBy: assigner, allowedBy: w.admin, run: func(a string) func(uint) error {
				return func(actor uint) error {
					_, err := w.c.CreateUserWithAssignments(ctx, w.newUser("assign-"+a), "",
						[]ProjectAssignment{{ProjectID: w.projA, Role: "project_viewer"}}, actor, false)
					return err
				}
			}, grantGate: func() { w.grantToRole(assignerRole, permUsersWrite) }},
		}
	})
}

// TestCoreGateParity_UpdateRoleRequiresTheGrantedPermissions: the #169 rule the
// transports applied before UpdateRole (a role author cannot bundle a permission
// they do not hold) is decided in core as well. The global admin holds everything;
// a users.write holder at the global scope passes the roles gates only if they
// also hold roles.read and roles.write, which is why the case uses a custom
// global role carrying exactly those two and asks to bundle secrets.delete.
func TestCoreGateParity_UpdateRoleRequiresTheGrantedPermissions(t *testing.T) {
	t.Parallel()
	w := newParityWorld(t)
	ctx := w.ctx
	author := w.customRole("parity-role-author")
	for _, p := range []string{"roles.read", "roles.write"} {
		require.NoError(t, w.st.AssignPermissionToRole(ctx, author.ID, w.permissionID(p)))
	}
	authorUser := seedUserWithRole(t, w.st, "parity-role-author-user", author.Name, Scope{})
	target := w.customRole("parity-role-target")

	del := w.permissionID("secrets.delete")
	_, _, err := w.c.UpdateRole(ctx, authorUser, &models.Role{ID: target.ID, Name: target.Name, Description: "d"}, &[]uint{del})
	require.ErrorIs(t, err, ErrPermissionDenied, "an author who does not hold secrets.delete must not bundle it")

	_, _, err = w.c.UpdateRole(ctx, w.admin, &models.Role{ID: target.ID, Name: target.Name, Description: "d"}, &[]uint{del})
	require.NoError(t, err, "the global admin holds every permission")
}

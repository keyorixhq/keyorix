// authz_core_gate_parity_test.go — #4161 (authzdiff waiver known-04): core decides
// the transports' route gates itself on the operations that used to rely on the
// transport alone. For every such operation: a principal the route gate refuses is
// refused by core with a typed ErrPermissionDenied (red before the gates), and a
// principal the route gate admits still succeeds (no behaviour regression).
//
// The denied principal is always one that holds a REAL grant short of the gate —
// a project_viewer for the secret-scoped write gates (secrets.read but not
// secrets.write), a project_admin of project A for the GLOBAL gates (roles.assign
// and users.read at A, nothing at the global scope) — so the test cannot pass by
// refusing an unknown or roleless actor. The strict differential sweep
// (server/authzdiff) covers every principal shape, including machines and PATs;
// these files are the per-op guard a reviewer can run in seconds. The fixture and
// the runner live here; the cases are split by family across
// authz_core_gate_parity_test.go (secrets and environments),
// authz_core_gate_parity_rbac_test.go (roles, users, groups) and
// authz_core_gate_parity_projects_test.go (projects, shares, invitations, bulk
// approve), one file per commit of the change.
package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	kxstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

type parityWorld struct {
	t     *testing.T
	c     *KeyorixCore
	st    *kxstore.LocalStorage
	ctx   context.Context
	admin uint

	projA, envA1, envA2, envA3, envA4 uint
	projB                             uint
	viewerA, devA, padminA, viewerB   uint
	viewerRoleID, devRoleID           uint
}

func newParityWorld(t *testing.T) *parityWorld {
	t.Helper()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	w := &parityWorld{t: t, c: c, st: st, ctx: ctx, admin: 1}
	c.SetCredentialDelivery(nil, "https://keyorix.example.invalid") // InviteGlobalWithLink issues a setup link

	pa, err := c.CreateProject(ctx, "parity-a", "")
	require.NoError(t, err)
	w.projA = pa.ID
	for i, dst := range []*uint{&w.envA1, &w.envA2, &w.envA3, &w.envA4} {
		e, err := c.CreateEnvironment(ctx, pa.ID, fmt.Sprintf("env-%d", i+1))
		require.NoError(t, err)
		*dst = e.ID
	}
	pb, err := c.CreateProject(ctx, "parity-b", "")
	require.NoError(t, err)
	w.projB = pb.ID

	w.viewerA = seedUserWithRole(t, st, "parity-viewer-a", "project_viewer", storage.Scope{ProjectID: w.projA})
	w.devA = seedUserWithRole(t, st, "parity-dev-a", "project_developer", storage.Scope{ProjectID: w.projA})
	w.padminA = seedUserWithRole(t, st, "parity-padmin-a", "project_admin", storage.Scope{ProjectID: w.projA})
	w.viewerB = seedUserWithRole(t, st, "parity-viewer-b", "project_viewer", storage.Scope{ProjectID: w.projB})
	vr, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	w.viewerRoleID = vr.ID
	dr, err := st.GetRoleByName(ctx, "project_developer")
	require.NoError(t, err)
	w.devRoleID = dr.ID
	return w
}

// secret creates a live secret owned by ownerID in env, value "v1".
func (w *parityWorld) secret(name string, env, ownerID uint) *models.SecretNode {
	w.t.Helper()
	s, err := w.c.CreateSecret(w.ctx, &CreateSecretRequest{
		Name: name, Value: []byte("v1"), ProjectID: w.projA, EnvironmentID: env, Type: "generic",
		CreatedBy: "parity", OwnerID: ownerID,
	})
	require.NoError(w.t, err)
	return s
}

// customRole creates a non-built-in role with no permissions.
func (w *parityWorld) customRole(name string) *models.Role {
	w.t.Helper()
	fn, err := identity.NewFoldedName(name)
	require.NoError(w.t, err)
	r, err := w.st.CreateRole(w.ctx, fn, "parity custom role")
	require.NoError(w.t, err)
	return r
}

func (w *parityWorld) group(name string) *models.Group {
	w.t.Helper()
	g, err := w.st.CreateGroup(w.ctx, &models.Group{Name: name, NameFolded: name})
	require.NoError(w.t, err)
	return g
}

func (w *parityWorld) permissionID(name string) uint {
	w.t.Helper()
	var p models.Permission
	require.NoError(w.t, w.st.DB().Where("name = ?", name).First(&p).Error)
	return p.ID
}

func (w *parityWorld) newUser(tag string) *CreateUserRequest {
	return &CreateUserRequest{
		Username: "parity-new-" + tag, Email: "parity-new-" + tag + "@example.com",
		DisplayName: "parity new " + tag, Password: "Zq7vTk2LmP9wXs!long-enough",
	}
}

// gateCase is one operation: run(attempt)(actor) drives it as actor; deniedBy is
// the principal the route gate refuses (red before #4161), allowedBy one it admits.
type gateCase struct {
	op        string
	deniedBy  uint
	allowedBy uint
	// run is built per attempt so each one gets fresh fixture rows where the
	// op consumes them (a role to delete, a user to create, ...).
	run func(attempt string) func(actor uint) error
}

// runGateCases drives every case: the refused principal gets a typed
// ErrPermissionDenied and nothing else, the admitted principal succeeds.
func runGateCases(t *testing.T, build func(w *parityWorld) []gateCase) {
	t.Helper()
	w := newParityWorld(t)
	for _, tc := range build(w) {
		t.Run(tc.op, func(t *testing.T) {
			err := tc.run("denied")(tc.deniedBy)
			require.Error(t, err, "%s: core allowed a principal the route gate refuses", tc.op)
			require.ErrorIs(t, err, ErrPermissionDenied, "%s: the refusal must be typed", tc.op)

			require.NoError(t, tc.run("allowed")(tc.allowedBy), "%s: an authorised caller must still succeed", tc.op)
		})
	}
}

// TestCoreGateParity_SecretsAndEnvironments: #4161 item 1. The per-secret write
// gates (secrets.write with the op's SecretAction) and the environment-level
// read/write gates. Denied: a project_viewer (secrets.read only); admitted: a
// project_developer.
func TestCoreGateParity_SecretsAndEnvironments(t *testing.T) {
	t.Parallel()
	runGateCases(t, func(w *parityWorld) []gateCase {
		ctx, t := w.ctx, w.t
		return []gateCase{
			{op: "secret.autorotate", deniedBy: w.viewerA, allowedBy: w.devA, run: func(a string) func(uint) error {
				s := w.secret("autorotate-"+a, w.envA1, w.admin)
				return func(actor uint) error {
					return w.c.SetSecretAutoRotate(ctx, s.ID, AutoRotateSpec{Enabled: true}, actor)
				}
			}},
			{op: "secret.rotate", deniedBy: w.viewerA, allowedBy: w.devA, run: func(a string) func(uint) error {
				s := w.secret("rotate-"+a, w.envA1, w.admin)
				return func(actor uint) error {
					_, err := w.c.RotateSecretOnDemand(ctx, s.ID, []byte("v2"), actor, "parity")
					return err
				}
			}},
			{op: "secret.rollback", deniedBy: w.viewerA, allowedBy: w.devA, run: func(a string) func(uint) error {
				s := w.secret("rollback-"+a, w.envA1, w.admin)
				_, err := w.c.RotateSecret(ctx, s.ID, []byte("v2"), w.admin, "admin")
				require.NoError(t, err)
				return func(actor uint) error {
					_, err := w.c.RollbackSecret(ctx, s.ID, 1, actor, "parity")
					return err
				}
			}},
			{op: "secret.copy", deniedBy: w.viewerA, allowedBy: w.devA, run: func(a string) func(uint) error {
				s := w.secret("copy-"+a, w.envA1, w.admin)
				return func(actor uint) error {
					_, err := w.c.CopySecret(ctx, s.ID, w.envA2, "copy-"+a, "parity", actor, "", "")
					return err
				}
			}},
			{op: "env.clone", deniedBy: w.viewerA, allowedBy: w.devA, run: func(a string) func(uint) error {
				w.secret("clone-src-"+a, w.envA1, w.admin)
				return func(actor uint) error {
					_, err := w.c.CloneEnvironment(ctx, w.projA, w.envA1, w.envA3, "parity", actor)
					return err
				}
			}},
			{op: "env.copy.secrets", deniedBy: w.viewerA, allowedBy: w.devA, run: func(a string) func(uint) error {
				w.secret("copyenv-src-"+a, w.envA1, w.admin)
				return func(actor uint) error {
					_, _, err := w.c.CopyEnvironmentSecrets(ctx, w.projA, w.envA1, w.envA4, "parity", actor, "", "")
					return err
				}
			}},
		}
	})
}

// TestCoreGateParity_InternalPseudoActorIsExempt: the trusted internal pseudo-actor
// (actorID 0, not a machine) that bootstrap, reconcilers and bulk paths use keeps
// its exemption — the gates refuse a real principal short of the permission, not
// the absence of one (the convention every other core ceiling already follows).
func TestCoreGateParity_InternalPseudoActorIsExempt(t *testing.T) {
	t.Parallel()
	w := newParityWorld(t)
	r := w.customRole("parity-system-actor")
	require.NoError(t, w.c.AssignPermissionToRole(w.ctx, 0, r.ID, w.permissionID("secrets.read"), false))
}

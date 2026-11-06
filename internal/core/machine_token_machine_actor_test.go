package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/require"
)

// A machine identity that holds roles.assign at the project may issue a token
// for another machine in that project when the transport tags it as the
// direct, self-acting caller. The ceiling is evaluated against the machine's
// own permissions, not against user 0.
func TestIssueMachineToken_MachineActorWithRolesAssignAllowed(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	caller, err := c.CreateMachineIdentity(ctx, 1, "token-caller", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	target, err := c.CreateMachineIdentity(ctx, 1, "token-target", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	adminRole, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignMachineRole(ctx, caller.ID, adminRole.ID, storage.Scope{ProjectID: 1}))

	res, err := c.IssueMachineToken(WithSelfMachineGranter(ctx, caller.ID), 1, target.ID, 0, IssueMachineTokenParams{Name: "by-machine"})
	require.NoError(t, err)
	require.NotEmpty(t, res.PlainToken)
}

func TestIssueMachineToken_MachineActorWithoutRolesAssignRefused(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	caller, err := c.CreateMachineIdentity(ctx, 1, "token-caller2", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	target, err := c.CreateMachineIdentity(ctx, 1, "token-target2", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	devRole, err := st.GetRoleByName(ctx, "project_developer")
	require.NoError(t, err)
	require.NoError(t, st.AssignMachineRole(ctx, caller.ID, devRole.ID, storage.Scope{ProjectID: 1}))

	_, err = c.IssueMachineToken(WithSelfMachineGranter(ctx, caller.ID), 1, target.ID, 0, IssueMachineTokenParams{Name: "nope"})
	require.ErrorIs(t, err, ErrMachinePrivilegeCeilingDenied)
}

// A machine caller cannot mint a credential for a machine that holds an
// administrative role, even when it holds roles.assign itself.
func TestIssueMachineToken_MachineActorCannotMintForAdminTierMachine(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	caller, err := c.CreateMachineIdentity(ctx, 1, "token-caller3", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	target, err := c.CreateMachineIdentity(ctx, 1, "token-target3", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	adminRole, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignMachineRole(ctx, caller.ID, adminRole.ID, storage.Scope{ProjectID: 1}))
	require.NoError(t, st.AssignMachineRole(ctx, target.ID, adminRole.ID, storage.Scope{ProjectID: 1}))

	_, err = c.IssueMachineToken(WithSelfMachineGranter(ctx, caller.ID), 1, target.ID, 0, IssueMachineTokenParams{Name: "nope"})
	require.ErrorIs(t, err, ErrMachinePrivilegeCeilingDenied)
}

// Without the self-granter tag, actor id 0 is still not a trusted caller, and
// a relayed (system proxy) tag is not treated as the machine acting as itself.
func TestIssueMachineToken_UntaggedOrRelayedZeroActorRefused(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	caller, err := c.CreateMachineIdentity(ctx, 1, "token-caller4", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	target, err := c.CreateMachineIdentity(ctx, 1, "token-target4", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	adminRole, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignMachineRole(ctx, caller.ID, adminRole.ID, storage.Scope{ProjectID: 1}))

	_, err = c.IssueMachineToken(ctx, 1, target.ID, 0, IssueMachineTokenParams{Name: "untagged"})
	require.ErrorIs(t, err, ErrMachinePrivilegeCeilingDenied)
	_, err = c.IssueMachineToken(WithSystemProxyMachineGranter(ctx, caller.ID), 1, target.ID, 0, IssueMachineTokenParams{Name: "relayed"})
	require.ErrorIs(t, err, ErrMachinePrivilegeCeilingDenied)
}

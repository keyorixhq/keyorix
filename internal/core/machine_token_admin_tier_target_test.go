package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/require"
)

// REVIEW-3993-DEEP-1 finding 2: for a machine actor the target check refused
// only bypass-flag roles. A peer holding a custom role that is admin-tier by
// its bundle (roleIsAdminTier) must be refused too, as the machine grant paths
// already do.
func TestIssueMachineToken_MachineActorCannotMintForCustomAdminTierPeer(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		perms []string
	}{
		{"secrets_delete", []string{"secrets.read", "secrets.delete"}},
		{"roles_assign", []string{"roles.assign"}},
		{"users_write", []string{"users.write"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, st, caller, peer := machineCallerFixture(t, "tier_"+tc.name)
			raw := addCallerCredential(t, st, caller.ID, "plain", "")
			role := customRoleWithPermissions(t, st, "peer_tier_"+tc.name, tc.perms...)
			require.NoError(t, st.AssignMachineRole(context.Background(), peer.ID, role.ID, storage.Scope{ProjectID: 1}))

			_, err := c.IssueMachineToken(machineCallerCtx(caller.ID, raw), 1, peer.ID, 0, IssueMachineTokenParams{Name: "act-as-peer"})
			require.ErrorIs(t, err, ErrMachinePrivilegeCeilingDenied)
			require.ErrorContains(t, err, "administrative roles")
			assertNoCredentialNamed(t, st, peer.ID, "act-as-peer")
		})
	}
}

// A peer whose custom role is not admin-tier is still reachable.
func TestIssueMachineToken_MachineActorMintsForNonAdminTierPeer(t *testing.T) {
	t.Parallel()
	c, st, caller, peer := machineCallerFixture(t, "tier_plain")
	raw := addCallerCredential(t, st, caller.ID, "plain", "")
	role := customRoleWithPermissions(t, st, "peer_tier_reader", "secrets.read")
	require.NoError(t, st.AssignMachineRole(context.Background(), peer.ID, role.ID, storage.Scope{ProjectID: 1}))

	res, err := c.IssueMachineToken(machineCallerCtx(caller.ID, raw), 1, peer.ID, 0, IssueMachineTokenParams{Name: "reader"})
	require.NoError(t, err)
	require.NotEmpty(t, res.PlainToken)
}

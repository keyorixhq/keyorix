package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// envInProject1 creates a live environment in project 1 for an
// environment-scoped grant.
func envInProject1(t *testing.T, c *KeyorixCore, name string) uint {
	t.Helper()
	env, err := c.storage.CreateEnvironment(context.Background(), &models.Environment{Name: name, ProjectID: 1})
	require.NoError(t, err)
	return env.ID
}

// REVIEW-3993-DEEP-2 finding 1: a machine caller holding only roles.assign
// minted a token for a non-admin-tier peer that reads and writes the project's
// secrets, and so gained permissions it is refused when it tries to grant
// itself the same role (requireGranterHoldsRolePermissions). The caller must
// hold every permission the target holds, at each scope the target holds it.
func TestIssueMachineToken_MachineActorCannotMintForPeerHoldingPermissionItLacks(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		envScope bool
	}{
		{"project_scope", false},
		{"environment_scope", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, st, caller, peer := machineCallerFixture(t, "lacks_"+tc.name)
			raw := addCallerCredential(t, st, caller.ID, "plain", "")
			reader := customRoleWithPermissions(t, st, "peer_rw_"+tc.name, "secrets.read", "secrets.write")
			scope := storage.Scope{ProjectID: 1}
			if tc.envScope {
				scope.EnvironmentID = envInProject1(t, c, "ceiling-prod-"+tc.name)
			}
			require.NoError(t, st.AssignMachineRole(context.Background(), peer.ID, reader.ID, scope))

			// The same caller may not grant itself that role directly.
			err := c.requireGranterHoldsRolePermissions(machineCallerCtx(caller.ID, raw), 0, reader.ID, scope, true)
			require.ErrorContains(t, err, "secrets.read")

			_, err = c.IssueMachineToken(machineCallerCtx(caller.ID, raw), 1, peer.ID, 0, IssueMachineTokenParams{Name: "act-as-peer"})
			require.ErrorIs(t, err, ErrMachinePrivilegeCeilingDenied)
			require.ErrorContains(t, err, "does not hold")
			assertNoCredentialNamed(t, st, peer.ID, "act-as-peer")
		})
	}
}

// The grant must cover the target's scope: a caller holding the permission
// only in a different environment is refused for a peer holding it in prod.
func TestIssueMachineToken_MachineActorPermissionInOtherEnvironmentDoesNotCover(t *testing.T) {
	t.Parallel()
	c, st, caller, peer := machineCallerFixture(t, "other_env")
	raw := addCallerCredential(t, st, caller.ID, "plain", "")
	reader := customRoleWithPermissions(t, st, "peer_reader_other_env", "secrets.read")
	staging := envInProject1(t, c, "ceiling-staging")
	prod := envInProject1(t, c, "ceiling-prod")
	ctx := context.Background()
	require.NoError(t, st.AssignMachineRole(ctx, caller.ID, reader.ID, storage.Scope{ProjectID: 1, EnvironmentID: staging}))
	require.NoError(t, st.AssignMachineRole(ctx, peer.ID, reader.ID, storage.Scope{ProjectID: 1, EnvironmentID: prod}))

	_, err := c.IssueMachineToken(machineCallerCtx(caller.ID, raw), 1, peer.ID, 0, IssueMachineTokenParams{Name: "act-as-peer"})
	require.ErrorIs(t, err, ErrMachinePrivilegeCeilingDenied)
	assertNoCredentialNamed(t, st, peer.ID, "act-as-peer")
}

// A caller that holds everything the peer holds may still issue for it,
// including when its project grant covers the peer's environment grant.
func TestIssueMachineToken_MachineActorMintsForPeerItCovers(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		envScope bool
	}{
		{"project_scope", false},
		{"environment_scope", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, st, caller, peer := machineCallerFixture(t, "covers_"+tc.name)
			raw := addCallerCredential(t, st, caller.ID, "plain", "")
			reader := customRoleWithPermissions(t, st, "peer_rw_cov_"+tc.name, "secrets.read", "secrets.write")
			ctx := context.Background()
			require.NoError(t, st.AssignMachineRole(ctx, caller.ID, reader.ID, storage.Scope{ProjectID: 1}))
			scope := storage.Scope{ProjectID: 1}
			if tc.envScope {
				scope.EnvironmentID = envInProject1(t, c, "ceiling-cov-"+tc.name)
			}
			require.NoError(t, st.AssignMachineRole(ctx, peer.ID, reader.ID, scope))

			res, err := c.IssueMachineToken(machineCallerCtx(caller.ID, raw), 1, peer.ID, 0, IssueMachineTokenParams{Name: "covered"})
			require.NoError(t, err)
			require.NotEmpty(t, res.PlainToken)
		})
	}
}

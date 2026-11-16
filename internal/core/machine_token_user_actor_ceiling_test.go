package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/require"
)

// fuzz-corpus#91 finding 1: a user holding only roles.assign at the project
// minted a token for a peer machine whose custom role carries permissions the
// user lacks, and so acted with them. The user must hold every permission the
// target holds, at each scope the target holds it (INV-CORE-01).
func TestIssueMachineToken_UserCannotMintForPeerHoldingPermissionItLacks(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	user, err := st.CreateUser(ctx, foldedTestUser(t, "mt-assigner", "mt-assigner@example.com"))
	require.NoError(t, err)
	assignOnly := customRoleWithPermissions(t, st, "user_assign_only", "roles.assign")
	require.NoError(t, st.AssignRole(ctx, user.ID, assignOnly.ID, storage.Scope{ProjectID: 1}))

	peer, err := c.CreateMachineIdentity(ctx, 1, "mt-peer-rw", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	rw := customRoleWithPermissions(t, st, "peer_rw_for_user", "secrets.read", "secrets.write")
	require.NoError(t, st.AssignMachineRole(ctx, peer.ID, rw.ID, storage.Scope{ProjectID: 1}))

	_, err = c.IssueMachineToken(ctx, 1, peer.ID, user.ID, IssueMachineTokenParams{Name: "act-as-peer"})
	require.ErrorIs(t, err, ErrMachinePrivilegeCeilingDenied)
	require.ErrorContains(t, err, "does not hold")
	assertNoCredentialNamed(t, st, peer.ID, "act-as-peer")
}

// A user that also holds everything the peer holds may still issue for it.
func TestIssueMachineToken_UserMintsForPeerItCovers(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	user, err := st.CreateUser(ctx, foldedTestUser(t, "mt-covering", "mt-covering@example.com"))
	require.NoError(t, err)
	assignOnly := customRoleWithPermissions(t, st, "user_assign_cov", "roles.assign")
	reader := customRoleWithPermissions(t, st, "peer_reader_cov", "secrets.read")
	require.NoError(t, st.AssignRole(ctx, user.ID, assignOnly.ID, storage.Scope{ProjectID: 1}))
	require.NoError(t, st.AssignRole(ctx, user.ID, reader.ID, storage.Scope{ProjectID: 1}))

	peer, err := c.CreateMachineIdentity(ctx, 1, "mt-peer-reader", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	require.NoError(t, st.AssignMachineRole(ctx, peer.ID, reader.ID, storage.Scope{ProjectID: 1}))

	res, err := c.IssueMachineToken(ctx, 1, peer.ID, user.ID, IssueMachineTokenParams{Name: "covered"})
	require.NoError(t, err)
	require.NotEmpty(t, res.PlainToken)
}

// A peer holding no role grants is still reachable with roles.assign alone:
// there is nothing to widen.
func TestIssueMachineToken_UserMintsForRolelessPeer(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	user, err := st.CreateUser(ctx, foldedTestUser(t, "mt-roleless", "mt-roleless@example.com"))
	require.NoError(t, err)
	assignOnly := customRoleWithPermissions(t, st, "user_assign_roleless", "roles.assign")
	require.NoError(t, st.AssignRole(ctx, user.ID, assignOnly.ID, storage.Scope{ProjectID: 1}))
	peer, err := c.CreateMachineIdentity(ctx, 1, "mt-peer-none", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)

	res, err := c.IssueMachineToken(ctx, 1, peer.ID, user.ID, IssueMachineTokenParams{Name: "plain"})
	require.NoError(t, err)
	require.NotEmpty(t, res.PlainToken)
}

// fuzz-corpus#91 finding 2: a restricted PAT (here limited to another project's
// permission set) that still allows roles.assign minted an unrestricted,
// non-expiring machine token. The restricted caller is refused; the same user
// without the restriction is not.
func TestIssueMachineToken_RestrictedPATCannotMint(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	user, err := st.CreateUser(ctx, foldedTestUser(t, "mt-pat", "mt-pat@example.com"))
	require.NoError(t, err)
	assignOnly := customRoleWithPermissions(t, st, "user_assign_pat", "roles.assign")
	require.NoError(t, st.AssignRole(ctx, user.ID, assignOnly.ID, storage.Scope{ProjectID: 1}))
	peer, err := c.CreateMachineIdentity(ctx, 1, "mt-peer-pat", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)

	restricted := WithPATRestriction(ctx, &PATRestriction{Permissions: []string{"roles.assign"}})
	_, err = c.IssueMachineToken(restricted, 1, peer.ID, user.ID, IssueMachineTokenParams{Name: "escape"})
	require.ErrorIs(t, err, ErrMachinePrivilegeCeilingDenied)
	require.ErrorContains(t, err, "restricted personal access token")
	assertNoCredentialNamed(t, st, peer.ID, "escape")

	res, err := c.IssueMachineToken(ctx, 1, peer.ID, user.ID, IssueMachineTokenParams{Name: "unrestricted-caller"})
	require.NoError(t, err)
	require.NotEmpty(t, res.PlainToken)
}

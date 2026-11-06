package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/require"
)

// customRoleWithPermissions creates a non-builtin role bundling exactly perms.
func customRoleWithPermissions(t *testing.T, st *store.LocalStorage, name string, perms ...string) *models.Role {
	t.Helper()
	ctx := context.Background()
	folded, err := identity.NewFoldedName(name)
	require.NoError(t, err)
	role, err := st.CreateRole(ctx, folded, "test-only")
	require.NoError(t, err)
	all, err := st.ListPermissions(ctx)
	require.NoError(t, err)
	want := map[string]bool{}
	for _, p := range perms {
		want[p] = true
	}
	for _, p := range all {
		if want[p.Name] {
			require.NoError(t, st.AssignPermissionToRole(ctx, role.ID, p.ID))
			delete(want, p.Name)
		}
	}
	require.Empty(t, want, "unknown permissions")
	return role
}

// addCallerCredential stores an opaque credential for machineID with the given
// AllowedCIDRs column and returns its plaintext.
func addCallerCredential(t *testing.T, st *store.LocalStorage, machineID uint, name, allowedCIDRs string) string {
	t.Helper()
	raw := machineTokenPrefix + "caller-" + name
	_, err := st.CreateMachineIdentityCredential(context.Background(), &models.MachineIdentityCredential{
		MachineIdentityID: machineID,
		Name:              name,
		TokenHash:         sha256Hex(raw),
		TokenPrefix:       raw[:len(machineTokenPrefix)+6],
		AllowedCIDRs:      allowedCIDRs,
	})
	require.NoError(t, err)
	return raw
}

// machineCallerCtx is what the REST and gRPC handlers build for a machine
// presenting presented as its bearer credential.
func machineCallerCtx(callerID uint, presented string) context.Context {
	return WithMachineCallerCredential(WithSelfMachineGranter(context.Background(), callerID), presented)
}

// machineCallerFixture: a caller holding a custom non-bypass role that bundles
// only roles.assign (the review's probe), and a plain peer in project 1.
func machineCallerFixture(t *testing.T, suffix string) (*KeyorixCore, *store.LocalStorage, *models.MachineIdentity, *models.MachineIdentity) {
	t.Helper()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	caller, err := c.CreateMachineIdentity(ctx, 1, "cred-caller-"+suffix, MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	peer, err := c.CreateMachineIdentity(ctx, 1, "cred-peer-"+suffix, MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	role := customRoleWithPermissions(t, st, "assign_only_"+suffix, "roles.assign")
	require.NoError(t, st.AssignMachineRole(ctx, caller.ID, role.ID, storage.Scope{ProjectID: 1}))
	return c, st, caller, peer
}

// An unrestricted opaque caller credential may issue for a peer.
func TestIssueMachineToken_UnrestrictedMachineCallerIssuesForPeer(t *testing.T) {
	t.Parallel()
	c, st, caller, peer := machineCallerFixture(t, "ok")
	raw := addCallerCredential(t, st, caller.ID, "plain", "")

	res, err := c.IssueMachineToken(machineCallerCtx(caller.ID, raw), 1, peer.ID, 0, IssueMachineTokenParams{Name: "for-peer"})
	require.NoError(t, err)
	require.NotEmpty(t, res.PlainToken)
}

// A machine may never mint a token for itself, even from an unrestricted
// credential: the review's {"name":"escape"} self-mint.
func TestIssueMachineToken_MachineCallerSelfMintRefused(t *testing.T) {
	t.Parallel()
	c, st, caller, _ := machineCallerFixture(t, "self")
	raw := addCallerCredential(t, st, caller.ID, "plain", "")

	_, err := c.IssueMachineToken(machineCallerCtx(caller.ID, raw), 1, caller.ID, 0, IssueMachineTokenParams{Name: "escape"})
	require.ErrorIs(t, err, ErrMachinePrivilegeCeilingDenied)
	require.ErrorContains(t, err, "for itself")
	assertNoCredentialNamed(t, st, caller.ID, "escape")
}

// A CIDR-restricted caller cannot produce an unrestricted token, for itself
// or for a peer.
func TestIssueMachineToken_CIDRRestrictedMachineCallerRefused(t *testing.T) {
	t.Parallel()
	c, st, caller, peer := machineCallerFixture(t, "cidr")
	raw := addCallerCredential(t, st, caller.ID, "restricted", `["10.0.0.0/8"]`)

	for _, target := range []uint{caller.ID, peer.ID} {
		_, err := c.IssueMachineToken(machineCallerCtx(caller.ID, raw), 1, target, 0, IssueMachineTokenParams{Name: "escape"})
		require.ErrorIs(t, err, ErrMachinePrivilegeCeilingDenied, "target %d", target)
		assertNoCredentialNamed(t, st, target, "escape")
	}
	// Still refused when the request asks for a restricted, expiring child:
	// the refusal is about the caller's credential, not the child's shape.
	_, err := c.IssueMachineToken(machineCallerCtx(caller.ID, raw), 1, peer.ID, 0, IssueMachineTokenParams{Name: "narrow", AllowedCIDRs: []string{"10.0.0.0/8"}})
	require.ErrorContains(t, err, "network-restricted")
}

// A federated (OIDC/Kubernetes JWT) caller cannot mint a durable opaque token,
// and neither can a caller whose credential the handler did not record.
func TestIssueMachineToken_FederatedOrUnidentifiedMachineCallerRefused(t *testing.T) {
	t.Parallel()
	c, st, caller, peer := machineCallerFixture(t, "oidc")

	jwt := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjaSJ9.c2ln"
	_, err := c.IssueMachineToken(machineCallerCtx(caller.ID, jwt), 1, peer.ID, 0, IssueMachineTokenParams{Name: "durable"})
	require.ErrorIs(t, err, ErrMachinePrivilegeCeilingDenied)
	require.ErrorContains(t, err, "federated")

	_, err = c.IssueMachineToken(WithSelfMachineGranter(context.Background(), caller.ID), 1, peer.ID, 0, IssueMachineTokenParams{Name: "untracked"})
	require.ErrorIs(t, err, ErrMachinePrivilegeCeilingDenied)
	assertNoCredentialNamed(t, st, peer.ID, "durable")
	assertNoCredentialNamed(t, st, peer.ID, "untracked")
}

// The presented credential must be a live credential of the caller itself:
// another machine's token, an unknown token or a revoked one is refused.
func TestIssueMachineToken_MachineCallerCredentialMustBeTheCallers(t *testing.T) {
	t.Parallel()
	c, st, caller, peer := machineCallerFixture(t, "own")
	other, err := c.CreateMachineIdentity(context.Background(), 1, "cred-other-own", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	othersRaw := addCallerCredential(t, st, other.ID, "others", "")

	_, err = c.IssueMachineToken(machineCallerCtx(caller.ID, othersRaw), 1, peer.ID, 0, IssueMachineTokenParams{Name: "x"})
	require.ErrorIs(t, err, ErrMachinePrivilegeCeilingDenied)

	_, err = c.IssueMachineToken(machineCallerCtx(caller.ID, machineTokenPrefix+"never-issued"), 1, peer.ID, 0, IssueMachineTokenParams{Name: "x"})
	require.ErrorIs(t, err, ErrMachinePrivilegeCeilingDenied)

	raw := addCallerCredential(t, st, caller.ID, "revoked", "")
	cred, err := st.GetMachineIdentityCredentialByHash(context.Background(), sha256Hex(raw))
	require.NoError(t, err)
	require.NoError(t, st.RevokeMachineIdentityCredential(context.Background(), 1, cred.ID))
	_, err = c.IssueMachineToken(machineCallerCtx(caller.ID, raw), 1, peer.ID, 0, IssueMachineTokenParams{Name: "x"})
	require.ErrorIs(t, err, ErrMachinePrivilegeCeilingDenied)
	assertNoCredentialNamed(t, st, peer.ID, "x")
}

func assertNoCredentialNamed(t *testing.T, st *store.LocalStorage, machineID uint, name string) {
	t.Helper()
	creds, err := st.ListMachineIdentityCredentials(context.Background(), machineID)
	require.NoError(t, err)
	for _, cr := range creds {
		require.NotEqual(t, name, cr.Name, "a refused issue must not store a credential")
	}
}

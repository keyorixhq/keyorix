package http

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	corestorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamDownstreamForMachineIdentities builds the standard #452/#507-style
// two-server harness: an "upstream" exercised through the REAL production
// NewRouter/handlers (including the new /api/v1/system/machine-identities,
// /machine-credentials, and /machine-oidc-bindings routes,
// server/http/handlers/machine_identities_proxy.go), and a "downstream"
// *core.KeyorixCore configured with storage.type: remote (ADR-049), pointed at
// "upstream" over real HTTP via store.RemoteStorage.
func newUpstreamDownstreamForMachineIdentities(t *testing.T) (upstream *core.KeyorixCore, downstream *core.KeyorixCore, projectID uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	upstream = newTestCore(t)
	upstreamToken := createNodeToken(t, upstream)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	upstreamRouter, err := NewRouter(cfg, upstream)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	t.Cleanup(upstreamSrv.Close)

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        upstreamSrv.URL,
		APIKey:         upstreamToken,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)
	downstream = core.NewKeyorixCore(rs)

	ctx := context.Background()
	project, err := upstream.CreateProject(ctx, "Machine Identities Test Project", "")
	require.NoError(t, err)
	return upstream, downstream, project.ID
}

func buildMachineIdentity(now time.Time, projectID uint, name string) *models.MachineIdentity {
	return &models.MachineIdentity{
		ProjectID:    projectID,
		Name:         name,
		IdentityType: core.MachineTypeCI,
		State:        core.MachineActive,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// TestRemoteStorageMachineIdentities_CreateGetListUpdate_RealServer proves the
// fix for CreateMachineIdentity/GetMachineIdentity/ListMachineIdentities/
// ListAllMachineIdentities/CountMachineIdentitiesByClassification: a machine
// identity is genuinely persisted on the upstream server via the DOWNSTREAM's
// RemoteStorage, fetchable by ID, and listed — all via storage.type: remote
// against a real router, not a protocol mock. Classification is set directly
// via CreateMachineIdentity's own row rather than a follow-up update:
// UpdateMachineIdentity/UpdateMachineIdentityProxy was DELETED (#1585,
// docs/adr-090-stale-fork-proxy-deletion.md) -- no live caller.
func TestRemoteStorageMachineIdentities_CreateGetListUpdate_RealServer(t *testing.T) {
	upstream, downstream, projectID := newUpstreamDownstreamForMachineIdentities(t)
	ctx := context.Background()
	now := time.Now()

	m, err := downstream.Storage().CreateMachineIdentity(ctx, buildMachineIdentity(now, projectID, "ci-runner"))
	require.NoError(t, err, "creating a machine identity must succeed via storage.type: remote")
	require.NotZero(t, m.ID, "the upstream must assign a real ID")
	assert.Equal(t, "ci-runner", m.Name)
	assert.Equal(t, core.MachineActive, m.State)

	// Confirm it is a REAL row in the upstream's own storage.
	direct, err := upstream.Storage().GetMachineIdentity(ctx, m.ID)
	require.NoError(t, err)
	assert.Equal(t, "ci-runner", direct.Name)

	// GetMachineIdentity via the downstream round-trips every field correctly.
	fetched, err := downstream.Storage().GetMachineIdentity(ctx, m.ID)
	require.NoError(t, err)
	assert.Equal(t, m.ID, fetched.ID)
	assert.Equal(t, m.Name, fetched.Name)
	assert.Equal(t, m.IdentityType, fetched.IdentityType)

	// A second identity, then list both back via ListMachineIdentities and
	// ListAllMachineIdentities.
	_, err = downstream.Storage().CreateMachineIdentity(ctx, buildMachineIdentity(now, projectID, "k8s-workload"))
	require.NoError(t, err)

	rows, err := downstream.Storage().ListMachineIdentities(ctx, projectID)
	require.NoError(t, err)
	require.Len(t, rows, 2)

	all, err := downstream.Storage().ListAllMachineIdentities(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(all), 2)

	// Classification is set at creation time (UpdateMachineIdentity, the only
	// way to change it post-create, was deleted -- #1585) and is genuinely
	// persisted on the upstream.
	confidential := buildMachineIdentity(now, projectID, "classified-runner")
	confidential.Classification = "confidential"
	createdConfidential, err := downstream.Storage().CreateMachineIdentity(ctx, confidential)
	require.NoError(t, err)
	reFetched, err := upstream.Storage().GetMachineIdentity(ctx, createdConfidential.ID)
	require.NoError(t, err)
	assert.Equal(t, "confidential", reFetched.Classification, "the classification must be visible directly on the upstream's own storage")

	counts, err := downstream.Storage().CountMachineIdentitiesByClassification(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, counts["confidential"])
}

// TestRemoteStorageMachineIdentities_GetNotFound_RealServer proves a clean
// not-found error for a nonexistent machine identity ID.
func TestRemoteStorageMachineIdentities_GetNotFound_RealServer(t *testing.T) {
	_, downstream, _ := newUpstreamDownstreamForMachineIdentities(t)
	ctx := context.Background()

	_, err := downstream.Storage().GetMachineIdentity(ctx, 999999)
	require.Error(t, err)
}

// TestRemoteStorageMachineIdentities_TransitionState_RealServer proves the fix
// for TransitionMachineIdentityState end-to-end: core.TransitionMachineIdentity,
// run against the DOWNSTREAM's RemoteStorage, drives the exact same conditional
// write against the upstream, and a legal transition is genuinely persisted.
func TestRemoteStorageMachineIdentities_TransitionState_RealServer(t *testing.T) {
	upstream, downstream, projectID := newUpstreamDownstreamForMachineIdentities(t)
	ctx := context.Background()
	now := time.Now()

	m, err := downstream.Storage().CreateMachineIdentity(ctx, buildMachineIdentity(now, projectID, "transition-test"))
	require.NoError(t, err)

	transitioned, err := downstream.TransitionMachineIdentity(ctx, projectID, m.ID, core.MachineSuspended, 1)
	require.NoError(t, err, "a legal transition must succeed via storage.type: remote")
	assert.Equal(t, core.MachineSuspended, transitioned.State)

	direct, err := upstream.Storage().GetMachineIdentity(ctx, m.ID)
	require.NoError(t, err)
	assert.Equal(t, core.MachineSuspended, direct.State, "the transition must be visible directly on the upstream's own storage")

	// Revoking stamps RevokedAt, and revoked is terminal — a subsequent
	// transition attempt must fail, exactly as it does against a local backend.
	revoked, err := downstream.TransitionMachineIdentity(ctx, projectID, m.ID, core.MachineRevoked, 1)
	require.NoError(t, err)
	require.NotNil(t, revoked.RevokedAt)

	_, err = downstream.TransitionMachineIdentity(ctx, projectID, m.ID, core.MachineActive, 1)
	require.Error(t, err, "revoked is terminal — reactivating a revoked machine identity must fail")
}

// TestRemoteStorageMachineIdentities_TransitionState_ConcurrentRaceIsSerialized_RealServer
// is the concurrency test for the #518 atomicity fix: N goroutines on the SAME
// downstream (storage.type: remote) core.KeyorixCore race to transition the SAME
// machine identity concurrently — one set toward "revoked", the rest toward
// "suspended" — starting from the identity's initial "active" state. Without
// TransitionMachineIdentityState's conditional write, a naive Lock-then-Update
// proxy pair would let a "suspended" writer silently win after a "revoked"
// writer already committed (#388), un-revoking a just-revoked identity. This
// proves that, under storage.type: remote against a REAL upstream server (not a
// mock), at most one revoke ever succeeds and the final persisted state is never
// un-revoked once a revoke has committed.
func TestRemoteStorageMachineIdentities_TransitionState_ConcurrentRaceIsSerialized_RealServer(t *testing.T) {
	upstream, downstream, projectID := newUpstreamDownstreamForMachineIdentities(t)
	ctx := context.Background()
	now := time.Now()

	m, err := downstream.Storage().CreateMachineIdentity(ctx, buildMachineIdentity(now, projectID, "race-test"))
	require.NoError(t, err)

	const n = 8
	var wg sync.WaitGroup
	successes := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			to := core.MachineSuspended
			if i%2 == 0 {
				to = core.MachineRevoked
			}
			_, err := downstream.TransitionMachineIdentity(ctx, projectID, m.ID, to, 1)
			successes[i] = err == nil
		}(i)
	}
	wg.Wait()

	// Whatever the final state, it must be internally consistent: if ANY revoke
	// succeeded, the persisted state must be "revoked" (terminal) — never
	// silently un-revoked by a racing suspend that observed a stale pre-revoke
	// read.
	//
	// winners is 1 OR 2, not always exactly 1: machineTransitions allows
	// active->suspended->revoked as a legitimate TWO-HOP chain (suspended is
	// NOT terminal), so it's possible for one racer to win active->suspended
	// and a DIFFERENT racer — one that happened to read the resulting
	// "suspended" row via its own LockMachineIdentityForUpdate call rather
	// than a stale "active" snapshot — to then legitimately win
	// suspended->revoked. That is a real, correctly-serialized second
	// transition, not a broken invariant: each individual conditional write is
	// still gated on its own fromState still being current at commit time
	// (#388), and machineTransitions[MachineRevoked] is empty, so once
	// *any* revoke commits, no further transition (from either "target") can
	// ever succeed — a 2-winner outcome is therefore only ever reachable via
	// exactly that suspended->revoked order, never revoked->anything.
	direct, err := upstream.Storage().GetMachineIdentity(ctx, m.ID)
	require.NoError(t, err)
	assert.Contains(t, []string{core.MachineSuspended, core.MachineRevoked}, direct.State)

	winners := 0
	revokeWon := false
	for i, ok := range successes {
		if ok {
			winners++
			if i%2 == 0 {
				revokeWon = true
			}
		}
	}
	require.GreaterOrEqualf(t, winners, 1, "at least one racer transitioning from the same pre-transition state must win (#388)")
	require.LessOrEqualf(t, winners, 2, "at most 2 winners are ever possible: one hop from active, optionally followed by one legal suspended->revoked hop")
	if revokeWon {
		assert.Equal(t, core.MachineRevoked, direct.State, "once a revoke commits, the persisted state must never be un-revoked")
	}
	if winners == 2 {
		// The only 2-hop chain the state machine allows from "active" is
		// active->suspended->revoked (revoked is terminal, suspended is not),
		// so a 2-winner outcome must always end in "revoked".
		assert.Equal(t, core.MachineRevoked, direct.State,
			"a legitimate second hop is only ever suspended->revoked, so 2 winners must end in the revoked state")
	}
}

// buildMachineIdentityCredential mirrors what internal/core.IssueMachineToken
// computes before calling storage.CreateMachineIdentityCredential — an
// already-hashed credential row (the raw token itself is shown once at
// issuance and never persisted).
func buildMachineIdentityCredential(now time.Time, machineID uint, tokenHash string) *models.MachineIdentityCredential {
	return &models.MachineIdentityCredential{
		MachineIdentityID: machineID,
		Name:              "ci token",
		TokenHash:         tokenHash,
		TokenPrefix:       "kx_machine_ab12cd",
		CreatedAt:         now,
	}
}

// TestRemoteStorageMachineIdentities_CredentialCreateGetHashListRevokeTouch_RealServer
// proves the fix for CreateMachineIdentityCredential/
// GetMachineIdentityCredentialByHash/GetMachineIdentityCredentialByID/
// ListMachineIdentityCredentials/ListActiveMachineIdentityCredentials/
// UpdateMachineIdentityCredential/CountMachineIdentityCredentialsByClassification/
// RevokeMachineIdentityCredential/TouchMachineIdentityCredential.
func TestRemoteStorageMachineIdentities_CredentialCreateGetHashListRevokeTouch_RealServer(t *testing.T) {
	upstream, downstream, projectID := newUpstreamDownstreamForMachineIdentities(t)
	ctx := context.Background()
	now := time.Now()

	m, err := downstream.Storage().CreateMachineIdentity(ctx, buildMachineIdentity(now, projectID, "cred-test"))
	require.NoError(t, err)

	const hash = "deadbeef00112233445566778899aabbccddeeff0011223344556677889900"
	cred, err := downstream.Storage().CreateMachineIdentityCredential(ctx, buildMachineIdentityCredential(now, m.ID, hash))
	require.NoError(t, err, "creating a machine credential must succeed via storage.type: remote")
	require.NotZero(t, cred.ID)

	// The upstream's own row carries the hash (never the raw token, which the
	// caller never had a reason to send in the first place).
	direct, err := upstream.Storage().GetMachineIdentityCredentialByID(ctx, cred.ID)
	require.NoError(t, err)
	assert.Equal(t, hash, direct.TokenHash)

	// GetMachineIdentityCredentialByHash via the downstream — the lookup
	// core.ValidateMachineToken relies on for machine-token authentication.
	byHash, err := downstream.Storage().GetMachineIdentityCredentialByHash(ctx, hash)
	require.NoError(t, err)
	assert.Equal(t, cred.ID, byHash.ID)

	byID, err := downstream.Storage().GetMachineIdentityCredentialByID(ctx, cred.ID)
	require.NoError(t, err)
	assert.Equal(t, cred.MachineIdentityID, byID.MachineIdentityID)

	rows, err := downstream.Storage().ListMachineIdentityCredentials(ctx, m.ID)
	require.NoError(t, err)
	require.Len(t, rows, 1)

	active, err := downstream.Storage().ListActiveMachineIdentityCredentials(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(active), 1)

	// UpdateMachineIdentityCredential persists a classification change.
	byID.Classification = "restricted"
	require.NoError(t, downstream.Storage().UpdateMachineIdentityCredential(ctx, byID))
	reFetched, err := upstream.Storage().GetMachineIdentityCredentialByID(ctx, cred.ID)
	require.NoError(t, err)
	assert.Equal(t, "restricted", reFetched.Classification)

	counts, err := downstream.Storage().CountMachineIdentityCredentialsByClassification(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, counts["restricted"])

	// TouchMachineIdentityCredential updates LastUsedAt.
	require.NoError(t, downstream.Storage().TouchMachineIdentityCredential(ctx, cred.ID, now, time.Minute))
	touched, err := upstream.Storage().GetMachineIdentityCredentialByID(ctx, cred.ID)
	require.NoError(t, err)
	require.NotNil(t, touched.LastUsedAt)

	// RevokeMachineIdentityCredential flips Revoked and is visible directly on
	// the upstream.
	require.NoError(t, downstream.Storage().RevokeMachineIdentityCredential(ctx, projectID, cred.ID))
	revoked, err := upstream.Storage().GetMachineIdentityCredentialByID(ctx, cred.ID)
	require.NoError(t, err)
	assert.True(t, revoked.Revoked)

	// Now excluded from the active list.
	activeAfter, err := downstream.Storage().ListActiveMachineIdentityCredentials(ctx)
	require.NoError(t, err)
	for _, c := range activeAfter {
		assert.NotEqual(t, cred.ID, c.ID, "a revoked credential must not appear in the active list")
	}
}

// TestRemoteStorageMachineIdentities_RevokeCredential_CrossTenantRejected_RealServer
// proves the #1551 fix: a caller reaching RevokeMachineIdentityCredentialProxy
// directly (as this test does, exactly like a caller holding raw system.write
// but not going through core.RevokeMachineToken's own client-side ownership
// check) cannot revoke a credential by naming a project it doesn't actually
// belong to. Before the fix, the wire carried no project_id at all and the
// upstream revoked by credential ID alone — this scenario would have
// succeeded. A positive control at the end proves the SAME credential is
// still revocable when the caller names its real project, so this isn't
// coincidentally rejecting every revoke.
func TestRemoteStorageMachineIdentities_RevokeCredential_CrossTenantRejected_RealServer(t *testing.T) {
	upstream, downstream, projectID := newUpstreamDownstreamForMachineIdentities(t)
	ctx := context.Background()
	now := time.Now()

	m, err := downstream.Storage().CreateMachineIdentity(ctx, buildMachineIdentity(now, projectID, "cross-tenant-test"))
	require.NoError(t, err)

	const hash = "cafef00d00112233445566778899aabbccddeeff0011223344556677889900"
	cred, err := downstream.Storage().CreateMachineIdentityCredential(ctx, buildMachineIdentityCredential(now, m.ID, hash))
	require.NoError(t, err)

	wrongProjectID := projectID + 999
	err = downstream.Storage().RevokeMachineIdentityCredential(ctx, wrongProjectID, cred.ID)
	require.Error(t, err, "revoking with a project_id the credential's machine doesn't belong to must be rejected")

	// The credential must still be live on the upstream — the rejected call
	// must not have revoked it anyway.
	stillLive, err := upstream.Storage().GetMachineIdentityCredentialByID(ctx, cred.ID)
	require.NoError(t, err)
	assert.False(t, stillLive.Revoked, "a cross-tenant revoke attempt must not revoke the credential")

	// Positive control: the same credential, same caller, correct project_id.
	require.NoError(t, downstream.Storage().RevokeMachineIdentityCredential(ctx, projectID, cred.ID))
	revoked, err := upstream.Storage().GetMachineIdentityCredentialByID(ctx, cred.ID)
	require.NoError(t, err)
	assert.True(t, revoked.Revoked, "revoking with the credential's real project_id must still succeed")
}

// TestRemoteStorageMachineIdentities_RoleGrantAssignRemoveListIDs_RealServer
// proves the fix for AssignMachineRole/RemoveMachineRole/GetMachineRoleIDsAt/
// GetMachineRoles.
func TestRemoteStorageMachineIdentities_RoleGrantAssignRemoveListIDs_RealServer(t *testing.T) {
	upstream, downstream, projectID := newUpstreamDownstreamForMachineIdentities(t)
	ctx := context.Background()
	now := time.Now()

	m, err := downstream.Storage().CreateMachineIdentity(ctx, buildMachineIdentity(now, projectID, "role-test"))
	require.NoError(t, err)

	machineRoleTestName, err := identity.NewFoldedName("machine-role-test")
	require.NoError(t, err)
	role, err := upstream.Storage().CreateRole(ctx, machineRoleTestName, "test")
	require.NoError(t, err)

	scope := corestorage.Scope{ProjectID: projectID, EnvironmentID: 0}
	require.NoError(t, downstream.Storage().AssignMachineRole(ctx, m.ID, role.ID, scope), "granting a machine role must succeed via storage.type: remote")

	// The grant is a REAL row on the upstream.
	ids, err := upstream.Storage().GetMachineRoleIDsAt(ctx, m.ID, scope)
	require.NoError(t, err)
	assert.Contains(t, ids, role.ID)

	// GetMachineRoleIDsAt/GetMachineRoles via the downstream.
	idsViaDownstream, err := downstream.Storage().GetMachineRoleIDsAt(ctx, m.ID, scope)
	require.NoError(t, err)
	assert.Contains(t, idsViaDownstream, role.ID)

	roles, err := downstream.Storage().GetMachineRoles(ctx, m.ID)
	require.NoError(t, err)
	require.Len(t, roles, 1)
	assert.Equal(t, role.Name, roles[0].Name)

	// A second concurrent grant of the same (machine, role, scope) must fail
	// (mirrors LocalStorage's own AssignMachineRole semantics).
	err = downstream.Storage().AssignMachineRole(ctx, m.ID, role.ID, scope)
	require.Error(t, err, "granting the same role twice must fail, exactly as against a local backend")

	// RemoveMachineRole revokes the grant; a second remove of the same grant
	// must fail (already gone).
	require.NoError(t, downstream.Storage().RemoveMachineRole(ctx, m.ID, role.ID, scope))
	idsAfter, err := upstream.Storage().GetMachineRoleIDsAt(ctx, m.ID, scope)
	require.NoError(t, err)
	assert.NotContains(t, idsAfter, role.ID)

	err = downstream.Storage().RemoveMachineRole(ctx, m.ID, role.ID, scope)
	require.Error(t, err, "removing an already-removed grant must fail")
}

// TestRemoteStorageMachineIdentities_OIDCBindingCreateGetListDelete_RealServer
// proves the fix for GetMachineByOIDCSubject/ListOIDCBindings/
// GetOIDCBindingByID/DeleteOIDCBinding, and confirms CreateOIDCBinding's fix.
//
// ADR-085 (Accepted, 2026-08-25) closed CreateOIDCBindingProxy's
// isNodeCredentialRequest(r) exemption — the branch this test used to exercise
// let ANY node credential route around core.CreateOIDCBinding's install-wide
// admin-authority check (requireAuthorityForRole against "system_admin"). That
// check resolves authority via scopedRoleIDs (internal/core/authz.go), which
// walks ONLY a user's direct and group role grants — a machine identity's own
// MachineIdentityRole grants were never in that resolution path, bypass or no
// bypass. So closing the exemption doesn't narrow machine-actor creation to
// "admin-tier machines only" — no machine actor, however permissioned, can
// ever satisfy this specific ceiling; only a human system_admin user can. The
// binding used for the rest of this test (Get/List/Delete round-trip) is
// therefore seeded directly on the upstream, and the downstream create is
// asserted denied — the ceiling-table row
// (TestSystemWriteCeiling_CreateOIDCBindingProxy_NodeCredential_StillBypassesAdminAuthority,
// system_write_ceiling_table_test.go) pins the same denial for a bare node
// credential specifically.
func TestRemoteStorageMachineIdentities_OIDCBindingCreateGetListDelete_RealServer(t *testing.T) {
	upstream, downstream, projectID := newUpstreamDownstreamForMachineIdentities(t)
	ctx := context.Background()
	now := time.Now()

	m, err := downstream.Storage().CreateMachineIdentity(ctx, buildMachineIdentity(now, projectID, "oidc-test"))
	require.NoError(t, err)

	_, err = downstream.Storage().CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
		MachineIdentityID: m.ID,
		Issuer:            "https://issuer.example",
		Subject:           "system:serviceaccount:default:ci-runner",
		CreatedAt:         now,
	})
	require.Error(t, err, "ADR-085: no machine actor, however permissioned, can create an OIDC binding — only a human system_admin can")

	binding, err := upstream.Storage().CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
		MachineIdentityID: m.ID,
		Issuer:            "https://issuer.example",
		Subject:           "system:serviceaccount:default:ci-runner",
		CreatedAt:         now,
	})
	require.NoError(t, err)
	require.NotZero(t, binding.ID)

	// A REAL row on the upstream.
	direct, err := upstream.Storage().GetOIDCBindingByID(ctx, binding.ID)
	require.NoError(t, err)
	assert.Equal(t, "https://issuer.example", direct.Issuer)

	// GetMachineByOIDCSubject/ListOIDCBindings/GetOIDCBindingByID via the downstream.
	resolved, err := downstream.Storage().GetMachineByOIDCSubject(ctx, "https://issuer.example", "system:serviceaccount:default:ci-runner")
	require.NoError(t, err)
	assert.Equal(t, m.ID, resolved.ID)

	bindings, err := downstream.Storage().ListOIDCBindings(ctx, m.ID)
	require.NoError(t, err)
	require.Len(t, bindings, 1)

	fetched, err := downstream.Storage().GetOIDCBindingByID(ctx, binding.ID)
	require.NoError(t, err)
	assert.Equal(t, binding.Subject, fetched.Subject)

	// A second binding with the SAME (issuer, subject) must fail (unique index).
	_, err = downstream.Storage().CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
		MachineIdentityID: m.ID,
		Issuer:            "https://issuer.example",
		Subject:           "system:serviceaccount:default:ci-runner",
		CreatedAt:         now,
	})
	require.Error(t, err, "a duplicate (issuer, subject) binding must fail, exactly as against a local backend")

	// DeleteOIDCBinding removes it; a second delete must fail (already gone).
	require.NoError(t, downstream.Storage().DeleteOIDCBinding(ctx, binding.ID))
	_, err = upstream.Storage().GetOIDCBindingByID(ctx, binding.ID)
	require.Error(t, err, "the deletion must be visible directly on the upstream's own storage")

	err = downstream.Storage().DeleteOIDCBinding(ctx, binding.ID)
	require.Error(t, err, "deleting an already-deleted binding must fail")

	// GetMachineByOIDCSubject for an unbound subject must cleanly not-found.
	_, err = downstream.Storage().GetMachineByOIDCSubject(ctx, "https://issuer.example", "no-such-subject")
	require.Error(t, err)
}

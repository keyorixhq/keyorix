// remote_storage_conformance_tranche3_test.go — issue #1808, tranche 3.
//
// Selection: TestReportConformancePopulation mechanically derived 200 real
// (non-stub) *RemoteStorage methods with no TestConformance_ test after
// tranche 2 (#1824, 7 methods). This tranche covers 7 more, spanning the
// DESTRUCTIVE and AUTHZ-CARRYING buckets (tranche 2 exhausted the highest-
// priority pure-DESTRUCTIVE-with-no-extra-ceiling methods):
//
//	DeleteProject, RemoveAllProjectRoleGrants, RevokeBreakGlassActivation,
//	AssignRoleWithExpiry, AssignMachineRole, ClearProjectSecretOwnership,
//	TransitionSecretStatus
//
// Deliberately NOT included, same reasoning discipline as tranche 2's
// DeleteUser exclusion:
//
//   - DeleteUser: still excluded (multi-step core cascade, not a raw-
//     primitive comparison — needs its own dedicated tranche).
//   - VerifyLoginCredentials / VerifyMFALoginCredentials: the literal
//     authentication gate. Excluded this tranche because a fair conformance
//     test needs real password/TOTP enrollment fixtures, not a shallow
//     struct comparison — disproportionate setup cost for one tranche, but
//     HIGH priority for the next one given its blast radius.
//   - RecordLoginAttempt / CountRecentLoginAttempts / PruneLoginAttempts:
//     flagged, not covered. This repo's own CLAUDE.md documents a prior,
//     independently-confirmed defect class in exactly this area (a
//     RemoteStorage login-attempt no-op) — worth prioritizing next tranche
//     precisely because history says this neighborhood bites.
//
// Two methods in this tranche required going beyond the tranche-2 pattern:
//
//  1. RevokeBreakGlassActivation's proxy handler hard-403s any caller with
//     actorID()==0 (server/http/handlers/break_glass_proxy.go) — the
//     shared harness's node/machine credential (h.rs) cannot drive this
//     route at all. This test mints a second RemoteStorage client
//     authenticated with a real user session (createTestToken, the same
//     helper newConformanceHarness's own setup chain already calls
//     indirectly via createNodeToken) pointed at the same httptest server.
//
//  2. AssignRoleWithExpiry and AssignMachineRole both route through
//     core's requireGranterHoldsRolePermissions ceiling
//     (internal/core/authz.go), which unconditionally refuses ANY
//     permission-carrying role grant when the acting principal is a
//     machine/node credential relayed through a /system proxy route
//     (isSelfMachineGrant is only ever set by non-proxy handlers, per that
//     function's own doc comment) — confirmed by the existing
//     TestAssignMachineRoleProxy_HappyPath_S21 fixture, which seeds its
//     role via a raw DB insert with zero attached permissions for exactly
//     this reason. Both tests below use a zero-permission role for the
//     same reason, matching established convention rather than fighting a
//     pre-existing, already-covered design constraint.
package http

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// --- DeleteProject ---

func TestConformance_DeleteProject(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newEmptyProject := func(suffix string) *models.Project {
		p, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-dp-"+suffix, "", []string{"dev"})
		require.NoError(t, err)
		return p
	}

	localProject := newEmptyProject("local")
	localSecret, err := h.ls.CreateSecret(ctx, &models.SecretNode{
		Name: "conformance-dp-secret-local", ProjectID: localProject.ID, EnvironmentID: h.environmentID, Type: "password",
	})
	require.NoError(t, err)
	require.NoError(t, h.ls.DeleteProject(ctx, localProject.ID))

	remoteProject := newEmptyProject("remote")
	remoteSecret, err := h.ls.CreateSecret(ctx, &models.SecretNode{
		Name: "conformance-dp-secret-remote", ProjectID: remoteProject.ID, EnvironmentID: h.environmentID, Type: "password",
	})
	require.NoError(t, err)
	require.NoError(t, h.rs.DeleteProject(ctx, remoteProject.ID),
		"RemoteStorage.DeleteProject must succeed for a project that genuinely exists")

	// GetProject applies GORM's default soft-delete scope (deleted_at IS
	// NULL), so a genuinely soft-deleted project becomes not-found through
	// it -- there is no GetProjectIncludingDeleted primitive to check the
	// DeletedAt timestamp directly, so "no longer retrievable" is the
	// conformance signal on both paths.
	_, localErr := h.ls.GetProject(ctx, localProject.ID)
	_, remoteErr := h.ls.GetProject(ctx, remoteProject.ID)
	assert.Error(t, localErr, "sanity: the local project must no longer be retrievable")
	assert.Error(t, remoteErr,
		"the project deleted via RemoteStorage must actually be gone server-side, not just report success")

	// The cascade (local_secrets.go's deleteProjectCascade) must reach the
	// project's own secrets identically on both paths -- a route that only
	// soft-deletes the project row itself would leave orphaned live secrets
	// behind, unreachable through the UI but still occupying storage and
	// still matchable by name on project recreation.
	_, localSecretErr := h.ls.GetSecret(ctx, localSecret.ID)
	_, remoteSecretErr := h.ls.GetSecret(ctx, remoteSecret.ID)
	assert.Error(t, localSecretErr, "sanity: the local project's secret must be gone after cascade")
	assert.Error(t, remoteSecretErr,
		"the remote project's secret must also be gone after RemoteStorage.DeleteProject's cascade")

	localEnvs, err := h.ls.ListEnvironmentsByProject(ctx, localProject.ID)
	require.NoError(t, err)
	remoteEnvs, err := h.ls.ListEnvironmentsByProject(ctx, remoteProject.ID)
	require.NoError(t, err)
	assert.Empty(t, localEnvs, "sanity: the local project's environments must be soft-deleted (excluded by default scope)")
	assert.Empty(t, remoteEnvs, "the remote project's environments must also be soft-deleted after the cascade")
}

// --- RemoveAllProjectRoleGrants ---

func TestConformance_RemoveAllProjectRoleGrants(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	// A role with NO attached permissions: RemoveAllProjectRoleGrantsProxy
	// routes through core.RemoveProjectMember's guardLastProjectAdmin, which
	// only fires for a roles.assign holder -- using a non-privileged role
	// keeps this test's DESTRUCTIVE-blast-radius scope (grant removal
	// fidelity) separate from that ceiling's own, already-covered behavior.
	roleName, err := identity.NewFoldedName("conformance-raprg-role")
	require.NoError(t, err)
	role, err := h.ls.CreateRole(ctx, roleName, "conformance test role")
	require.NoError(t, err)

	newGrantedUser := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-raprg-" + suffix, Email: "conformance-raprg-" + suffix + "@example.com",
			DisplayName: "Conformance RemoveAllProjectRoleGrants " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		// Grant at BOTH project scope (environment_id=0) and environment
		// scope -- RemoveAllProjectRoleGrants must remove every row for
		// (userID, projectID) across ALL environments, not just one.
		require.NoError(t, h.ls.AssignRole(ctx, user.ID, role.ID, coreStorage.Scope{ProjectID: h.projectID}))
		require.NoError(t, h.ls.AssignRole(ctx, user.ID, role.ID, coreStorage.Scope{ProjectID: h.projectID, EnvironmentID: h.environmentID}))
		return user
	}

	localUser := newGrantedUser("local")
	require.NoError(t, h.ls.RemoveAllProjectRoleGrants(ctx, localUser.ID, h.projectID))

	remoteUser := newGrantedUser("remote")
	require.NoError(t, h.rs.RemoveAllProjectRoleGrants(ctx, remoteUser.ID, h.projectID),
		"RemoteStorage.RemoveAllProjectRoleGrants must succeed for a non-roles.assign grantee")

	localIDs, err := h.ls.GetUserRoleIDsExact(ctx, localUser.ID, coreStorage.Scope{ProjectID: h.projectID})
	require.NoError(t, err)
	remoteIDs, err := h.ls.GetUserRoleIDsExact(ctx, remoteUser.ID, coreStorage.Scope{ProjectID: h.projectID})
	require.NoError(t, err)
	assert.Empty(t, localIDs, "sanity: the local user's project-scope grant must be gone")
	assert.Empty(t, remoteIDs, "the remote user's project-scope grant must actually be gone server-side")

	localEnvIDs, err := h.ls.GetUserRoleIDsExact(ctx, localUser.ID, coreStorage.Scope{ProjectID: h.projectID, EnvironmentID: h.environmentID})
	require.NoError(t, err)
	remoteEnvIDs, err := h.ls.GetUserRoleIDsExact(ctx, remoteUser.ID, coreStorage.Scope{ProjectID: h.projectID, EnvironmentID: h.environmentID})
	require.NoError(t, err)
	assert.Empty(t, localEnvIDs, "sanity: the local user's environment-scope grant must ALSO be gone -- "+
		"RemoveAllProjectRoleGrants is documented to remove every environment's grant, not just the project-level one")
	assert.Empty(t, remoteEnvIDs, "the remote user's environment-scope grant must ALSO be gone server-side -- "+
		"a wire call that only cleared the project-level (environment_id=0) row would leave a stale, "+
		"still-effective environment-scope grant behind")
}

// --- RevokeBreakGlassActivation ---

func TestConformance_RevokeBreakGlassActivation(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	// RevokeBreakGlassActivationProxy hard-403s any caller whose actorID()
	// is 0 (server/http/handlers/break_glass_proxy.go: "revoking a
	// break-glass activation requires an attributable, authenticated human
	// caller") -- h.rs's node/machine credential cannot drive this route at
	// all. Mint a second RemoteStorage client authenticated with a real
	// user session against the SAME server instead.
	userToken := createTestToken(t, h.upstreamCore)
	rsAsUser, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: h.server.URL, APIKey: userToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)

	// Zero-permission role, same reasoning as AssignRoleWithExpiry/
	// AssignMachineRole below -- the proxy's own RemoveUserRole side effect
	// (see next comment) would otherwise risk tripping the last-project-
	// admin ceiling.
	roleName, err := identity.NewFoldedName("conformance-rbga-role")
	require.NoError(t, err)
	role, err := h.ls.CreateRole(ctx, roleName, "conformance test role")
	require.NoError(t, err)

	newActiveActivation := func(suffix string) (*models.User, *models.BreakGlassActivation) {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-rbga-" + suffix, Email: "conformance-rbga-" + suffix + "@example.com",
			DisplayName: "Conformance RevokeBreakGlass " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		require.NoError(t, h.ls.AssignRole(ctx, user.ID, role.ID, coreStorage.Scope{ProjectID: h.projectID}))
		activation, err := h.ls.CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
			ProjectID: h.projectID, UserID: user.ID, RoleID: role.ID, RoleName: role.Name,
			Justification: "conformance test", State: "active",
		})
		require.NoError(t, err)
		return user, activation
	}

	_, localActivation := newActiveActivation("local")
	revokedAt := time.Now().UTC()
	localMatchErr := h.ls.RevokeBreakGlassActivation(ctx, localActivation.ID, h.adminUserID, 0, revokedAt)
	require.NoError(t, localMatchErr, "sanity: revoking a genuinely active activation must succeed")

	_, remoteActivation := newActiveActivation("remote")
	// Pass a DIFFERENT revokedBy than the authenticated actor (h.adminUserID)
	// deliberately -- the proxy handler must derive RevokedBy from the
	// authenticated session, never trust the wire-supplied value (the same
	// never-trust-client-asserted-attribution discipline as #1542's
	// CreatedBy preservation). A bogus caller-supplied actorID here that
	// silently landed in the DB would forge attribution on a security
	// control's own audit trail.
	const forgedRevokedBy = 999999
	require.NoError(t, rsAsUser.RevokeBreakGlassActivation(ctx, remoteActivation.ID, forgedRevokedBy, 0, revokedAt),
		"RemoteStorage.RevokeBreakGlassActivation must succeed for a genuinely active activation")

	localAfter, err := h.ls.GetBreakGlassActivation(ctx, localActivation.ID)
	require.NoError(t, err)
	remoteAfter, err := h.ls.GetBreakGlassActivation(ctx, remoteActivation.ID)
	require.NoError(t, err)

	assert.Equal(t, "revoked", localAfter.State, "sanity: local state must transition to revoked")
	assert.Equal(t, "revoked", remoteAfter.State, "the remote activation's state must actually be revoked server-side")
	assert.NotEqual(t, uint(forgedRevokedBy), remoteAfter.RevokedBy,
		"RevokedBy must be derived from the authenticated session server-side, not trusted from the wire -- "+
			"the handler discards the caller-supplied value and substitutes the real actor")

	// Wrong-state precondition: an already-revoked activation must refuse a
	// second revoke on both paths (storage.ErrBreakGlassNotActive), not
	// silently no-op success.
	assert.Error(t, h.ls.RevokeBreakGlassActivation(ctx, localActivation.ID, h.adminUserID, 0, time.Now().UTC()))
	assert.Error(t, rsAsUser.RevokeBreakGlassActivation(ctx, remoteActivation.ID, h.adminUserID, 0, time.Now().UTC()))
}

// --- AssignRoleWithExpiry ---

func TestConformance_AssignRoleWithExpiry(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	roleName, err := identity.NewFoldedName("conformance-arwe-role")
	require.NoError(t, err)
	role, err := h.ls.CreateRole(ctx, roleName, "conformance test role")
	require.NoError(t, err)

	newUser := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-arwe-" + suffix, Email: "conformance-arwe-" + suffix + "@example.com",
			DisplayName: "Conformance AssignRoleWithExpiry " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		return user
	}

	expiresAt := time.Now().Add(time.Hour).UTC()
	scope := coreStorage.Scope{ProjectID: h.projectID}

	localUser := newUser("local")
	require.NoError(t, h.ls.AssignRoleWithExpiry(ctx, localUser.ID, role.ID, scope, expiresAt))

	remoteUser := newUser("remote")
	require.NoError(t, h.rs.AssignRoleWithExpiry(ctx, remoteUser.ID, role.ID, scope, expiresAt),
		"RemoteStorage.AssignRoleWithExpiry must succeed for a zero-permission role grant")

	localIDs, err := h.ls.GetUserRoleIDsAt(ctx, localUser.ID, scope)
	require.NoError(t, err)
	remoteIDs, err := h.ls.GetUserRoleIDsAt(ctx, remoteUser.ID, scope)
	require.NoError(t, err)
	assert.Contains(t, localIDs, role.ID, "sanity: the local grant must be visible at the target scope")
	assert.Contains(t, remoteIDs, role.ID,
		"the remote grant must actually be visible server-side at the target scope, not just report success")
}

// --- AssignMachineRole ---

func TestConformance_AssignMachineRole(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	roleName, err := identity.NewFoldedName("conformance-amr-role")
	require.NoError(t, err)
	role, err := h.ls.CreateRole(ctx, roleName, "conformance test role")
	require.NoError(t, err)

	newMachine := func(suffix string) *models.MachineIdentity {
		mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-amr-mi-"+suffix, core.MachineTypeService, "conformance test machine", "", h.adminUserID, 0)
		require.NoError(t, err)
		return mi
	}

	scope := coreStorage.Scope{ProjectID: h.projectID}

	localMachine := newMachine("local")
	require.NoError(t, h.ls.AssignMachineRole(ctx, localMachine.ID, role.ID, scope))

	remoteMachine := newMachine("remote")
	require.NoError(t, h.rs.AssignMachineRole(ctx, remoteMachine.ID, role.ID, scope),
		"RemoteStorage.AssignMachineRole must succeed for a zero-permission role grant on a machine in the caller-supplied project")

	localIDs, err := h.ls.GetMachineRoleIDsAt(ctx, localMachine.ID, scope)
	require.NoError(t, err)
	remoteIDs, err := h.ls.GetMachineRoleIDsAt(ctx, remoteMachine.ID, scope)
	require.NoError(t, err)
	assert.Contains(t, localIDs, role.ID, "sanity: the local machine's grant must be visible at the target scope")
	assert.Contains(t, remoteIDs, role.ID,
		"the remote machine's grant must actually be visible server-side, not just report success")
}

// --- ClearProjectSecretOwnership ---

func TestConformance_ClearProjectSecretOwnership(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newOwnedSecret := func(ownerID uint, suffix string) uint {
		secret, err := h.ls.CreateSecret(ctx, &models.SecretNode{
			Name: "conformance-cpso-secret-" + suffix, ProjectID: h.projectID, EnvironmentID: h.environmentID,
			Type: "password", OwnerID: ownerID,
		})
		require.NoError(t, err)
		return secret.ID
	}

	newUser := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-cpso-" + suffix, Email: "conformance-cpso-" + suffix + "@example.com",
			DisplayName: "Conformance ClearProjectSecretOwnership " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		return user
	}

	localUser := newUser("local")
	localOwned := newOwnedSecret(localUser.ID, "local-owned")
	localBystander := newUser("local-bystander")
	localBystanderSecret := newOwnedSecret(localBystander.ID, "local-bystander")
	require.NoError(t, h.ls.ClearProjectSecretOwnership(ctx, localUser.ID, h.projectID))

	remoteUser := newUser("remote")
	remoteOwned := newOwnedSecret(remoteUser.ID, "remote-owned")
	remoteBystander := newUser("remote-bystander")
	remoteBystanderSecret := newOwnedSecret(remoteBystander.ID, "remote-bystander")
	require.NoError(t, h.rs.ClearProjectSecretOwnership(ctx, remoteUser.ID, h.projectID),
		"RemoteStorage.ClearProjectSecretOwnership must succeed for a user who genuinely owns secrets in the project")

	localAfter, err := h.ls.GetSecretsByIDs(ctx, []uint{localOwned, localBystanderSecret})
	require.NoError(t, err)
	remoteAfter, err := h.ls.GetSecretsByIDs(ctx, []uint{remoteOwned, remoteBystanderSecret})
	require.NoError(t, err)

	byID := func(secrets []*models.SecretNode, id uint) *models.SecretNode {
		for _, s := range secrets {
			if s.ID == id {
				return s
			}
		}
		t.Fatalf("secret %d not found in result set", id)
		return nil
	}
	assert.Equal(t, uint(0), byID(localAfter, localOwned).OwnerID, "sanity: the local owner's secret must be cleared")
	assert.Equal(t, uint(0), byID(remoteAfter, remoteOwned).OwnerID,
		"the remote owner's secret must actually be cleared server-side, not just report success")
	assert.Equal(t, localBystander.ID, byID(localAfter, localBystanderSecret).OwnerID,
		"sanity: a bystander's secret owned by a DIFFERENT user must survive")
	assert.Equal(t, remoteBystander.ID, byID(remoteAfter, remoteBystanderSecret).OwnerID,
		"a bystander's secret owned by a DIFFERENT user must survive the remote call too -- a dropped/ignored "+
			"user_id on the wire would clear ownership project-wide instead of scoping to the named user")
}

// --- TransitionSecretStatus ---

func TestConformance_TransitionSecretStatus(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newActiveSecret := func(suffix string) *models.SecretNode {
		secret, err := h.ls.CreateSecret(ctx, &models.SecretNode{
			Name: "conformance-tss-secret-" + suffix, ProjectID: h.projectID, EnvironmentID: h.environmentID,
			Type: "password", Status: "active",
		})
		require.NoError(t, err)
		fresh, err := h.ls.GetSecret(ctx, secret.ID)
		require.NoError(t, err)
		return fresh
	}

	// Wrong-fromStatus precondition must be a no-op (matched=false) on both
	// paths, and must not alter the row.
	localSecret := newActiveSecret("local")
	localMatchedWrong, err := h.ls.TransitionSecretStatus(ctx, localSecret, "suspended" /* wrong: it's "active" */)
	require.NoError(t, err)
	assert.False(t, localMatchedWrong, "sanity: a wrong fromStatus must not match")

	remoteSecret := newActiveSecret("remote")
	remoteMatchedWrong, err := h.rs.TransitionSecretStatus(ctx, remoteSecret, "suspended")
	require.NoError(t, err)
	assert.False(t, remoteMatchedWrong,
		"RemoteStorage.TransitionSecretStatus must report no match for a wrong fromStatus, not silently apply it")

	stillActive, err := h.ls.GetSecret(ctx, remoteSecret.ID)
	require.NoError(t, err)
	assert.Equal(t, "active", stillActive.Status, "a wrong-fromStatus transition attempt must not have altered the row")

	// Correct fromStatus: TransitionSecretStatusProxy deliberately (#G79)
	// re-fetches the row server-side and applies ONLY Status/UpdatedAt from
	// the wire body, discarding every other field the client's in-memory
	// struct carries -- a security-motivated narrowing (a client must not
	// rewrite arbitrary fields under cover of a status transition), not a
	// wire-fidelity bug. A fair comparison therefore mutates ONLY
	// Status/UpdatedAt before calling, matching what every real caller
	// (SuspendSecret/ResumeSecret) actually does.
	localSecret.Status = "suspended"
	localSecret.UpdatedAt = time.Now().UTC()
	localMatched, err := h.ls.TransitionSecretStatus(ctx, localSecret, "active")
	require.NoError(t, err)
	assert.True(t, localMatched, "sanity: the correct fromStatus must match")

	remoteSecret.Status = "suspended"
	remoteSecret.UpdatedAt = time.Now().UTC()
	remoteMatched, err := h.rs.TransitionSecretStatus(ctx, remoteSecret, "active")
	require.NoError(t, err)
	assert.True(t, remoteMatched, "RemoteStorage.TransitionSecretStatus must report a match for the correct fromStatus")

	persisted, err := h.ls.GetSecret(ctx, remoteSecret.ID)
	require.NoError(t, err)
	assert.Equal(t, "suspended", persisted.Status, "the status itself must have transitioned")

	// Compare each side's own sent struct against its own persisted result
	// (not local's row against remote's row -- they're two independently
	// seeded secrets with different IDs/Names/CreatedAt by construction).
	// The interesting comparison is the remote side: does the wire round
	// trip preserve every field the #G79 narrowing doesn't intentionally
	// discard? localPersisted is the in-process sanity baseline.
	localPersisted, err := h.ls.GetSecret(ctx, localSecret.ID)
	require.NoError(t, err)
	exclude := map[string]bool{
		"ValueStored": true, // gorm:"-" json:"-", never persisted/serialized by design
		// GORM auto-regenerates a struct field literally named UpdatedAt at
		// save time regardless of the caller-supplied value (confirmed: both
		// ls and rs diverge from what was sent by the same few microseconds
		// here, so this is a GORM convention, not a proxy-layer wire bug).
		"UpdatedAt": true,
	}
	assertFieldExhaustiveEqual(t, "LocalStorage.TransitionSecretStatus (sanity baseline)", localSecret, localPersisted, exclude)
	assertFieldExhaustiveEqual(t, "RemoteStorage.TransitionSecretStatus (wire round trip)", remoteSecret, persisted, exclude)
}

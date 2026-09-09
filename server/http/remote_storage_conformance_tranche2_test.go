// remote_storage_conformance_tranche2_test.go — issue #1808, tranche 2.
//
// Selection: TestReportConformancePopulation (remote_storage_conformance_population_test.go)
// mechanically derived 207 real (non-stub) *RemoteStorage methods with no
// TestConformance_ test after tranche 1 (#1812, 7 methods). All 207 were
// classified into DESTRUCTIVE / AUDIT-EMITTING / AUTHZ-CARRYING / NONE by
// blast radius (real evidence per method: the core/handler call site, not
// guesses). This tranche covers 7 methods, ALL from the DESTRUCTIVE bucket
// (highest priority per the task brief) — a dropped scope or filter here
// destroys the wrong thing:
//
//	DeleteSecret, RevokeMachineIdentityCredential,
//	RevokeAllPersonalAccessTokensForUser, DeleteExpiredRoleGrants,
//	DeleteSecretACLsByUserAndProject, TransitionMachineIdentityState,
//	RemoveGlobalAdminRoleGuarded
//
// DeleteUser (also DESTRUCTIVE, arguably the single highest blast-radius
// method in the whole population) was deliberately NOT included: unlike
// every method above, core.DeleteUser is a multi-step cascade (last-admin
// guard, deactivate, revoke sessions, revoke PATs, THEN soft-delete) that
// LocalStorage.DeleteUser's raw storage primitive does not reproduce on its
// own — a fair comparison needs comparing two FULL core.DeleteUser
// executions (one in-process, one over HTTP), not RemoteStorage against the
// raw LocalStorage primitive the other 7 methods below compare cleanly
// against. That's real, separate design work, not a checkbox this tranche
// had room for — left for a dedicated future tranche rather than rushed.
//
// Audit-emitting and authz-carrying methods are left for later tranches per
// the task brief's own priority order ("everything else waits").
package http

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// --- DeleteSecret ---

func TestConformance_DeleteSecret(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newSecret := func(name string) *models.SecretNode {
		return &models.SecretNode{Name: name, ProjectID: h.projectID, EnvironmentID: h.environmentID, Type: "password"}
	}

	localSecret, err := h.ls.CreateSecret(ctx, newSecret("conformance-ds-local"))
	require.NoError(t, err)
	remoteSecret, err := h.ls.CreateSecret(ctx, newSecret("conformance-ds-remote"))
	require.NoError(t, err)

	require.NoError(t, h.ls.DeleteSecret(ctx, localSecret.ID))
	require.NoError(t, h.rs.DeleteSecret(ctx, remoteSecret.ID),
		"RemoteStorage.DeleteSecret must succeed for a secret that genuinely exists")

	_, localErr := h.ls.GetSecret(ctx, localSecret.ID)
	_, remoteErr := h.ls.GetSecret(ctx, remoteSecret.ID)
	assert.Error(t, localErr, "sanity: a deleted secret must not be readable via the normal (non-deleted) getter")
	assert.Error(t, remoteErr,
		"the secret deleted via RemoteStorage must actually be gone server-side, not just report success -- "+
			"read back through the SAME LocalStorage instance the router wraps, not just trusting the HTTP response")

	// Deleting an already-deleted (or never-existent) secret must fail identically on both paths -- not silently
	// succeed a second time, which would mask a dropped-ID / wrong-route defect as false "idempotent" success.
	assert.Error(t, h.ls.DeleteSecret(ctx, localSecret.ID))
	assert.Error(t, h.rs.DeleteSecret(ctx, remoteSecret.ID))
}

// --- RevokeMachineIdentityCredential ---

func TestConformance_RevokeMachineIdentityCredential(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	otherProject, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-rmic-other-project", "", []string{"dev"})
	require.NoError(t, err)

	newCredential := func(suffix string) *models.MachineIdentityCredential {
		mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-rmic-mi-"+suffix, core.MachineTypeNode, "conformance test node", "", h.adminUserID, 0)
		require.NoError(t, err)
		cred, err := h.ls.CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
			MachineIdentityID: mi.ID,
			Name:              "conformance-rmic-cred-" + suffix,
			TokenHash:         "conformance-rmic-hash-" + suffix, // uniqueIndex
			TokenPrefix:       "kxm_" + suffix,
		})
		require.NoError(t, err)
		return cred
	}

	localCred := newCredential("local")
	require.NoError(t, h.ls.RevokeMachineIdentityCredential(ctx, h.projectID, localCred.ID))

	remoteCred := newCredential("remote")
	require.NoError(t, h.rs.RevokeMachineIdentityCredential(ctx, h.projectID, remoteCred.ID),
		"RemoteStorage.RevokeMachineIdentityCredential must succeed when the credential genuinely belongs to "+
			"the caller-supplied project")

	localAfter, err := h.ls.GetMachineIdentityCredentialByID(ctx, localCred.ID)
	require.NoError(t, err)
	remoteAfter, err := h.ls.GetMachineIdentityCredentialByID(ctx, remoteCred.ID)
	require.NoError(t, err)
	assert.True(t, localAfter.Revoked, "sanity: LocalStorage's own revoke must take effect")
	assert.True(t, remoteAfter.Revoked, "the credential revoked via RemoteStorage must actually be marked revoked server-side")

	// #1551 regression (server/http/handlers/machine_identities_proxy.go's own doc
	// comment on this exact route): a caller-supplied project_id that does NOT
	// match the credential's REAL owning project must not revoke it. The original
	// 2026-08-29 fix only checked "does the credential belong to the NAMED
	// project" -- a fact an attacker also knows, since it's exactly what they'd
	// attack with. The corrected version resolves the credential's real project
	// SERVER-SIDE and requires the caller to hold roles.assign there, using the
	// wire project_id only as a cross-check. Prove that still holds: supply a
	// real, different project as the claimed owner.
	wrongProjectCred := newCredential("wrongproject")
	err = h.rs.RevokeMachineIdentityCredential(ctx, otherProject.ID, wrongProjectCred.ID)
	assert.Error(t, err,
		"RemoteStorage.RevokeMachineIdentityCredential must refuse when the caller-supplied project_id does not "+
			"match the credential's real owning project (#1551) -- proves the server resolves the real project "+
			"itself rather than trusting the wire value to identify which tenant is being acted on")
	stillActive, err := h.ls.GetMachineIdentityCredentialByID(ctx, wrongProjectCred.ID)
	require.NoError(t, err)
	assert.False(t, stillActive.Revoked, "a cross-project revoke attempt must not actually revoke the credential")
}

// --- RevokeAllPersonalAccessTokensForUser ---

func TestConformance_RevokeAllPersonalAccessTokensForUser(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newUserWithPATs := func(suffix string, n int) (*models.User, []string) {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-ratpfu-" + suffix, Email: "conformance-ratpfu-" + suffix + "@example.com",
			DisplayName: "Conformance RevokeAllPATs " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		var hashes []string
		for i := 0; i < n; i++ {
			hash := fmt.Sprintf("conformance-ratpfu-hash-%s-%d", suffix, i)
			_, err := h.ls.CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{
				UserID: user.ID, Name: fmt.Sprintf("token-%d", i), TokenHash: hash, TokenPrefix: "kx_pat_" + suffix,
			})
			require.NoError(t, err)
			hashes = append(hashes, hash)
		}
		return user, hashes
	}

	// A bystander user whose tokens must NOT be touched by either call below --
	// this is the scope-drop risk: userID silently dropped/wrong would revoke
	// the wrong user's (or every user's) tokens.
	bystander, bystanderHashes := newUserWithPATs("bystander", 1)

	localUser, localHashes := newUserWithPATs("local", 2)
	localRevoked, err := h.ls.RevokeAllPersonalAccessTokensForUser(ctx, localUser.ID)
	require.NoError(t, err)
	assert.ElementsMatch(t, localHashes, localRevoked, "sanity: LocalStorage must return exactly the hashes it revoked")

	remoteUser, remoteHashes := newUserWithPATs("remote", 2)
	remoteRevoked, err := h.rs.RevokeAllPersonalAccessTokensForUser(ctx, remoteUser.ID)
	require.NoError(t, err)
	assert.ElementsMatch(t, remoteHashes, remoteRevoked,
		"RemoteStorage.RevokeAllPersonalAccessTokensForUser must return exactly the hashes it revoked for THIS "+
			"user -- a dropped/wrong userID on the wire would return the wrong set (or none)")

	localTokens, err := h.ls.ListPersonalAccessTokensByUser(ctx, localUser.ID)
	require.NoError(t, err)
	for _, tok := range localTokens {
		assert.True(t, tok.Revoked, "sanity: every one of the local user's tokens must be revoked")
	}
	remoteTokens, err := h.ls.ListPersonalAccessTokensByUser(ctx, remoteUser.ID)
	require.NoError(t, err)
	for _, tok := range remoteTokens {
		assert.True(t, tok.Revoked,
			"every one of the remote user's tokens must actually be revoked server-side, not just reported so")
	}

	bystanderTokens, err := h.ls.ListPersonalAccessTokensByUser(ctx, bystander.ID)
	require.NoError(t, err)
	require.Len(t, bystanderTokens, len(bystanderHashes))
	for _, tok := range bystanderTokens {
		assert.False(t, tok.Revoked,
			"a bystander user's tokens must survive both revocations untouched -- proves the scope is the "+
				"caller-supplied userID, not accidentally every user's tokens")
	}
}

// --- DeleteExpiredRoleGrants ---

func TestConformance_DeleteExpiredRoleGrants(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	role, err := h.ls.GetRoleByName(ctx, "system_viewer")
	require.NoError(t, err)
	scope := coreStorage.Scope{ProjectID: h.projectID, EnvironmentID: h.environmentID}

	past := time.Now().Add(-1 * time.Hour).UTC().Truncate(time.Second)
	future := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	cutoff := time.Now().UTC()

	newExpiringGrant := func(username string, expiresAt time.Time) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: username, Email: username + "@example.com", DisplayName: username, IsActive: true,
		})
		require.NoError(t, err)
		require.NoError(t, h.ls.AssignRoleWithExpiry(ctx, user.ID, role.ID, scope, expiresAt))
		return user
	}

	// Local side: one already-expired grant (must be purged) and one
	// not-yet-expired grant (must survive) -- the dropped-filter risk this
	// method exists to catch is exactly "before applied to the wrong rows".
	localExpiredUser := newExpiringGrant("conformance-derg-local-expired", past)
	localFutureUser := newExpiringGrant("conformance-derg-local-future", future)
	localRemoved, err := h.ls.DeleteExpiredRoleGrants(ctx, cutoff)
	require.NoError(t, err)
	assert.True(t, containsRoleGrant(toRoleAssignments(localRemoved), role.ID, scope) ||
		len(localRemoved) > 0, "sanity: LocalStorage must report at least the one grant it purged")

	remoteExpiredUser := newExpiringGrant("conformance-derg-remote-expired", past)
	remoteFutureUser := newExpiringGrant("conformance-derg-remote-future", future)
	remoteRemoved, err := h.rs.DeleteExpiredRoleGrants(ctx, cutoff)
	require.NoError(t, err,
		"RemoteStorage.DeleteExpiredRoleGrants must succeed and report the purged grants")

	localAfterExpired, err := h.ls.GetUserRoles(ctx, localExpiredUser.ID)
	require.NoError(t, err)
	localAfterFuture, err := h.ls.GetUserRoles(ctx, localFutureUser.ID)
	require.NoError(t, err)
	remoteAfterExpired, err := h.ls.GetUserRoles(ctx, remoteExpiredUser.ID)
	require.NoError(t, err)
	remoteAfterFuture, err := h.ls.GetUserRoles(ctx, remoteFutureUser.ID)
	require.NoError(t, err)

	assert.False(t, containsRoleByID(localAfterExpired, role.ID), "sanity: the local expired grant must be gone")
	assert.True(t, containsRoleByID(localAfterFuture, role.ID), "sanity: the local not-yet-expired grant must survive")
	assert.False(t, containsRoleByID(remoteAfterExpired, role.ID),
		"RemoteStorage.DeleteExpiredRoleGrants must actually purge the expired grant server-side")
	assert.True(t, containsRoleByID(remoteAfterFuture, role.ID),
		"RemoteStorage.DeleteExpiredRoleGrants must NOT touch a grant that has not yet expired -- a dropped or "+
			"widened 'before' filter on the wire would purge this one too")

	_ = remoteRemoved
}

func containsRoleByID(roles []*models.Role, roleID uint) bool {
	for _, r := range roles {
		if r.ID == roleID {
			return true
		}
	}
	return false
}

func toRoleAssignments(in []coreStorage.RoleAssignment) []coreStorage.RoleAssignment { return in }

// --- DeleteSecretACLsByUserAndProject ---

func TestConformance_DeleteSecretACLsByUserAndProject(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	otherProject, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-dsabup-other-project", "", []string{"dev"})
	require.NoError(t, err)

	newUser := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-dsabup-" + suffix, Email: "conformance-dsabup-" + suffix + "@example.com",
			DisplayName: "Conformance DeleteACLs " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		return user
	}
	newACL := func(userID, projectID uint, secretSuffix string) uint {
		secret, err := h.ls.CreateSecret(ctx, &models.SecretNode{
			Name: "conformance-dsabup-secret-" + secretSuffix, ProjectID: projectID, EnvironmentID: h.environmentID, Type: "password",
		})
		require.NoError(t, err)
		require.NoError(t, h.ls.CreateOrUpdateSecretACL(ctx, &models.SecretACL{
			SecretID: secret.ID, UserID: userID, Permissions: `["secrets.read"]`, GrantedBy: h.adminUserID,
		}))
		return secret.ID
	}

	localUser := newUser("local")
	newACL(localUser.ID, h.projectID, "local")
	require.NoError(t, h.ls.DeleteSecretACLsByUserAndProject(ctx, localUser.ID, h.projectID))

	// remoteUser holds an ACL in BOTH the target project and a different one --
	// the "other project" ACL must survive. This is the scope-drop risk: a
	// dropped/ignored project_id on the wire would wipe every ACL the user
	// holds anywhere, not just in the named project.
	remoteUser := newUser("remote")
	newACL(remoteUser.ID, h.projectID, "remote-target")
	remoteOtherSecretID := newACL(remoteUser.ID, otherProject.ID, "remote-other")

	require.NoError(t, h.rs.DeleteSecretACLsByUserAndProject(ctx, remoteUser.ID, h.projectID),
		"RemoteStorage.DeleteSecretACLsByUserAndProject must succeed for a user who genuinely holds an ACL in "+
			"the named project")

	localACLsAfter, err := h.ls.ListSecretACLsByUser(ctx, localUser.ID)
	require.NoError(t, err)
	assert.Empty(t, localACLsAfter, "sanity: the local user's ACL in the target project must be gone")

	remoteACLsAfter, err := h.ls.ListSecretACLsByUser(ctx, remoteUser.ID)
	require.NoError(t, err)
	require.Len(t, remoteACLsAfter, 1,
		"the remote user's ACL in the NAMED project must actually be gone server-side, and the ACL in the "+
			"OTHER project must survive -- a dropped or ignored project_id on the wire would either wipe both "+
			"(too broad) or neither (silently no-op)")
	assert.Equal(t, remoteOtherSecretID, remoteACLsAfter[0].SecretID,
		"the surviving ACL must be the one in the other project, not a leftover copy of the deleted one")
}

// --- TransitionMachineIdentityState ---

func TestConformance_TransitionMachineIdentityState(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	// CreateMachineIdentity always creates in MachineActive state (there is no
	// "create pending" path) -- see internal/core/machine_identities.go. The
	// wrong-fromState scenario below therefore uses "suspended" as the
	// (incorrect) fromState: suspended->active IS a legal transition shape per
	// core.machineTransitions, so it passes TransitionMachineIdentityStateProxy's
	// own IsValidMachineTransition legality guard and reaches the CAS write --
	// which is the thing this test needs to exercise. Using an actually-illegal
	// shape (e.g. active->active) is rejected by that guard before ever reaching
	// the CAS layer, which would test the guard, not the CAS no-op guarantee.
	newActiveMachine := func(suffix string) *models.MachineIdentity {
		mi, err := h.upstreamCore.CreateMachineIdentity(ctx, h.projectID, "conformance-tmis-"+suffix, core.MachineTypeNode, "conformance test node", "", h.adminUserID, 0)
		require.NoError(t, err)
		fresh, err := h.ls.GetMachineIdentity(ctx, mi.ID)
		require.NoError(t, err)
		require.Equal(t, "active", fresh.State, "sanity: CreateMachineIdentity always creates active")
		return fresh
	}

	// Wrong-fromState precondition must be a no-op (Matched=false), on both
	// paths, and must NOT alter the row -- this is the CAS guarantee the wire
	// call must preserve, not just "return success".
	localMI := newActiveMachine("local")
	localMatchedWrong, err := h.ls.TransitionMachineIdentityState(ctx, localMI, "suspended" /* wrong: it's "active" */)
	require.NoError(t, err)
	assert.False(t, localMatchedWrong, "sanity: a wrong fromState must not match")

	remoteMI := newActiveMachine("remote")
	remoteMatchedWrong, err := h.rs.TransitionMachineIdentityState(ctx, remoteMI, "suspended")
	require.NoError(t, err)
	assert.False(t, remoteMatchedWrong,
		"RemoteStorage.TransitionMachineIdentityState must report no match for a wrong fromState, not silently "+
			"apply the transition anyway")

	stillActive, err := h.ls.GetMachineIdentity(ctx, remoteMI.ID)
	require.NoError(t, err)
	assert.Equal(t, "active", stillActive.State,
		"a wrong-fromState transition attempt must not have altered the row at all")

	// Correct fromState: the transition must apply, and (Select("*") full-row
	// update) every field on the struct we sent must land -- Description is
	// the field-drop risk analogous to the historical AllowedCIDRs/ParentID
	// class, chosen here because it's a plain string with no legitimate
	// server-side override reason (unlike CreatedBy/Status in CreateSecret).
	// active->suspended is a legal transition per core.machineTransitions.
	localMI.State = "suspended"
	localMI.Description = "conformance transition description local"
	localMatched, err := h.ls.TransitionMachineIdentityState(ctx, localMI, "active")
	require.NoError(t, err)
	assert.True(t, localMatched, "sanity: the correct fromState must match")

	remoteMI.State = "suspended"
	remoteMI.Description = "conformance transition description remote"
	remoteMatched, err := h.rs.TransitionMachineIdentityState(ctx, remoteMI, "active")
	require.NoError(t, err)
	assert.True(t, remoteMatched,
		"RemoteStorage.TransitionMachineIdentityState must report a match for the correct fromState")

	persisted, err := h.ls.GetMachineIdentity(ctx, remoteMI.ID)
	require.NoError(t, err)
	assert.Equal(t, "suspended", persisted.State, "the state itself must have transitioned")
	assert.Equal(t, "conformance transition description remote", persisted.Description,
		"every field on the struct sent over the wire must land, not just State -- this is a full-row "+
			"conditional update (Select(\"*\")) on the LocalStorage side, so a wire struct that silently "+
			"dropped a field would silently WIPE it here, not just fail to update it")
}

// --- RemoveGlobalAdminRoleGuarded ---

func TestConformance_RemoveGlobalAdminRoleGuarded(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	adminRole, err := h.ls.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	globalScope := coreStorage.Scope{}

	newGlobalAdmin := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-rgarg-" + suffix, Email: "conformance-rgarg-" + suffix + "@example.com",
			DisplayName: "Conformance RemoveGlobalAdmin " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		require.NoError(t, h.ls.AssignRole(ctx, user.ID, adminRole.ID, globalScope))
		return user
	}

	// h.adminUserID and the harness's node credential already hold "admin" at
	// global scope, so removing either of the two users below never strands
	// the install -- this test is about wire fidelity and the #1816-adjacent
	// "ignored field" contract below, not re-proving internal/core's own
	// last-admin guard (already covered by TestGuardLastAdminDeactivation_*).
	localAdmin := newGlobalAdmin("local")
	require.NoError(t, h.ls.RemoveGlobalAdminRoleGuarded(ctx, localAdmin.ID, adminRole.ID, []uint{adminRole.ID}))

	remoteAdmin := newGlobalAdmin("remote")
	require.NoError(t, h.rs.RemoveGlobalAdminRoleGuarded(ctx, remoteAdmin.ID, adminRole.ID, []uint{adminRole.ID}),
		"RemoteStorage.RemoveGlobalAdminRoleGuarded must succeed for a genuine, non-last admin-role removal")

	localRolesAfter, err := h.ls.GetUserRoles(ctx, localAdmin.ID)
	require.NoError(t, err)
	remoteRolesAfter, err := h.ls.GetUserRoles(ctx, remoteAdmin.ID)
	require.NoError(t, err)
	assert.False(t, containsRoleByID(localRolesAfter, adminRole.ID), "sanity: the local admin role grant must actually be gone")
	assert.False(t, containsRoleByID(remoteRolesAfter, adminRole.ID),
		"the remote admin role grant must actually be gone server-side, not just report success")

	// server/http/handlers/rbac_role_grants_proxy.go's own doc comment on this
	// exact route (removeGlobalAdminRoleGuardedProxyWire): AdminRoleIDs is kept
	// on the wire for compatibility with older clients but is IGNORED --
	// ADR-085 routes every caller through core.RemoveUserRole, which resolves
	// the install-admin-role set SERVER-SIDE and never trusts a caller-supplied
	// set for the last-admin count. Prove the field is truly inert: send an
	// EMPTY (wrong) adminRoleIDs for another genuine, non-last removal, and
	// confirm it still succeeds correctly -- a client sending a garbage/stale
	// list must not accidentally SPOOF a false "would strand" refusal for a
	// removal that is actually safe (nor, the more dangerous direction as
	// covered by the raw LocalStorage primitive's OWN trust of this argument
	// two lines above, silently bypass a real one -- but that direction is
	// internal/core's own guard's job to prove, not this wire-fidelity test's).
	wireCompatAdmin := newGlobalAdmin("wire-compat")
	err = h.rs.RemoveGlobalAdminRoleGuarded(ctx, wireCompatAdmin.ID, adminRole.ID, nil)
	assert.NoError(t, err,
		"an empty/wrong client-supplied adminRoleIDs must NOT block a genuinely safe removal -- the server "+
			"ignores this field and resolves the real admin-role set itself (ADR-085)")
	wireCompatRolesAfter, err := h.ls.GetUserRoles(ctx, wireCompatAdmin.ID)
	require.NoError(t, err)
	assert.False(t, containsRoleByID(wireCompatRolesAfter, adminRole.ID),
		"the removal must have actually taken effect despite the empty adminRoleIDs argument")
}

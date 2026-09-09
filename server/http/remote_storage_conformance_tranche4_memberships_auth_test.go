// remote_storage_conformance_tranche4_memberships_auth_test.go — issue #1808,
// tranche 4.
//
// Assignment: cover the 8 methods in internal/storage/store/remote_memberships.go
// and the 8 methods in internal/storage/store/remote_auth.go named in the tranche
// brief:
//
//	remote_memberships.go: CountProjectMembershipsByUsers, CreateProjectMembership,
//	GetActiveProjectMembership, GetProjectMembership, ListProjectMemberships,
//	ListStaleInvitedMemberships, ListUserProjectMemberships,
//	TransitionProjectMembershipState
//
//	remote_auth.go: CountSetupTokensSince, CreateSetupToken, DeleteSession,
//	DeleteSessionsForUserExcept, GetSession, GetSetupTokenByHash,
//	MarkSetupTokenExpired, SupersedeActiveSetupTokens
//
// 15 of the 16 are covered below. One is deliberately skipped:
//
//   - TransitionProjectMembershipState: unlike every other "Transition*"/"CAS"
//     method already covered by this harness (TransitionMachineIdentityState,
//     TransitionSecretStatus — tranche 2/3), the server-side route backing
//     this one (TransitionMembershipProxy, project_memberships_proxy.go) is
//     NOT a raw passthrough onto storage.TransitionProjectMembershipState's
//     CAS primitive. It fully delegates to core.TransitionMembership, which
//     re-reads the row itself, derives fromState from that fresh read (the
//     wire's own from_state is accepted but explicitly documented as unused),
//     enforces canTransition legality service-side, and applies a role-grant
//     side effect (AddProjectMember) the raw primitive never does. A caller
//     cannot even PRODUCE the raw CAS's "wrong fromState -> no match" outcome
//     through this route: within one synchronous request there is no window
//     for the server's own fresh read to already be stale, so matched=false
//     is unreachable without genuine concurrency, and an illegal target state
//     surfaces as a different error shape (a generic STORAGE_ERROR, not the
//     matched=false wire contract every other CAS method here shares). A fair
//     conformance test would need to compare two FULL core.TransitionMembership
//     executions (one in-process, one over HTTP through a second, RemoteStorage
//     -backed core.KeyorixCore) rather than RemoteStorage against the raw
//     LocalStorage primitive — this is the exact same shape of problem tranche
//     2's own header names for excluding DeleteUser ("real, separate design
//     work, not a checkbox this tranche had room for"), and is left for a
//     dedicated future tranche for the identical reason, not faked here with a
//     shallow/tautological comparison.
//
// # Two wire-fidelity gaps found while building this tranche, NOT fixed here
//
// This tranche's own instructions are to add exactly one new test file and
// touch nothing else, so both of the following are documented and worked
// around (excluded from the relevant field-exhaustive comparison, with the
// gap spelled out inline at the exclusion) rather than repaired. Both match
// the #1573 "which machine identity performed this action" attribution
// pattern this codebase already carries for several other models.
//
//  1. SetupToken.CreatedByMachineIdentityID (remote_auth.go's CreateSetupToken):
//     remote_auth.go's own client-side setupTokenWire has no field for it at
//     all, while server/http/handlers/setup_tokens_proxy.go's
//     setupTokenProxyWire — the wire struct for the exact same JSON key,
//     "created_by_machine_identity_id" — does. CreateSetupTokenProxy derives
//     and PERSISTS the correct value from the authenticated caller
//     (machineID(r)) server-side, so the DATABASE row is correct; only the
//     HTTP response decoded back into the client's *models.SetupToken loses
//     it, because there is nowhere on that struct for the field to land. See
//     TestConformance_CreateSetupToken below, where this is demonstrated by
//     reading the persisted row directly (nonzero) alongside the wire-decoded
//     response (always zero). Fix: add a CreatedByMachineIdentityID field to
//     remote_auth.go's setupTokenWire (mirroring setupTokenProxyWire exactly)
//     and thread it through newSetupTokenWire/toModel.
//
//  2. ProjectMembership.InvitedByMachineIdentityID (remote_memberships.go's
//     CreateProjectMembership): worse than (1) — this one is missing from
//     BOTH sides of the wire. remote_memberships.go's membershipWire AND
//     server/http/handlers/project_memberships_proxy.go's membershipProxyWire
//     both lack the field entirely, so it never even reaches the JSON
//     envelope in either direction. CreateMembershipProxy also never derives
//     it from the authenticated caller the way CreateSetupTokenProxy does for
//     CreatedByMachineIdentityID (it only forces InvitedBy = actorID(r), not
//     an analogous InvitedByMachineIdentityID = machineID(r)) — so a
//     machine-authenticated node relay creating a membership over
//     storage.type: remote silently persists InvitedByMachineIdentityID as 0
//     no matter which machine identity actually performed the invite,
//     server-side DB row included, not just the HTTP response. This tranche's
//     TestConformance_CreateProjectMembership does not attempt to demonstrate
//     it (setting the field on the request wouldn't even round-trip to
//     compare against, since neither wire struct carries it) — flagged here
//     instead so it isn't lost. Fix needs three changes: add the field to
//     BOTH membershipWire and membershipProxyWire, and add
//     model.InvitedByMachineIdentityID = machineID(r) to CreateMembershipProxy
//     alongside its existing InvitedBy = actorID(r) line.
package http

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// --- CreateProjectMembership ---

func TestConformance_CreateProjectMembership(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	// A zero-permission role: CreateMembershipProxy routes the grant through
	// RequireGranterHoldsRolePermissions (#1578), which for a machine actor
	// relayed through a /system proxy route fails closed on ANY bundled
	// permission (isSelfMachineGrant is only ever set by non-proxy handlers) —
	// same reasoning tranche 3 documents for AssignRoleWithExpiry/
	// AssignMachineRole. A role with no permissions makes that loop a no-op.
	roleName, err := identity.NewFoldedName("conformance-cpm-role")
	require.NoError(t, err)
	role, err := h.ls.CreateRole(ctx, roleName, "conformance test role")
	require.NoError(t, err)

	newUser := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-cpm-" + suffix, Email: "conformance-cpm-" + suffix + "@example.com",
			DisplayName: "Conformance CreateProjectMembership " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		return user
	}

	invitedAt := time.Now().UTC().Truncate(time.Second)

	localUser := newUser("local")
	localSent := &models.ProjectMembership{
		ProjectID: h.projectID, UserID: localUser.ID, Role: role.Name, State: "invited",
		InvitedBy: h.adminUserID, InvitedAt: invitedAt,
	}
	_, err = h.ls.CreateProjectMembership(ctx, localSent)
	require.NoError(t, err)
	localPersisted, err := h.ls.GetProjectMembership(ctx, localSent.ID)
	require.NoError(t, err)
	localExclude := map[string]bool{
		"UpdatedAt": true, // GORM auto-sets this on Create -- confirmed the sole diff by running this test
	}
	assertFieldExhaustiveEqual(t, "LocalStorage.CreateProjectMembership (sanity baseline)", localSent, localPersisted, localExclude)

	remoteUser := newUser("remote")
	const forgedInvitedBy = 999999
	remoteSent := &models.ProjectMembership{
		ProjectID: h.projectID, UserID: remoteUser.ID, Role: role.Name, State: "invited",
		InvitedBy: forgedInvitedBy, InvitedAt: invitedAt,
	}
	remoteCreated, err := h.rs.CreateProjectMembership(ctx, remoteSent)
	require.NoError(t, err, "RemoteStorage.CreateProjectMembership must succeed for a zero-permission role and a genuine project/user")

	// G80-style forced-attribution check (#1578): InvitedBy must come from the
	// authenticated caller server-side, never the wire-supplied value.
	assert.NotEqual(t, uint(forgedInvitedBy), remoteCreated.InvitedBy,
		"InvitedBy must be derived from the authenticated caller server-side, never trusted from the wire")

	remotePersisted, err := h.ls.GetProjectMembership(ctx, remoteCreated.ID)
	require.NoError(t, err)

	requestExclude := map[string]bool{
		"ID":        true, // not yet assigned on the pre-create wire struct; response fidelity is checked separately below via remoteCreated
		"InvitedBy": true, // forged input, forced server-side -- asserted explicitly above
		"UpdatedAt": true, // GORM auto-set on Create
	}
	assertFieldExhaustiveEqual(t, "RemoteStorage.CreateProjectMembership (request fidelity: sent vs persisted)", remoteSent, remotePersisted, requestExclude)

	responseExclude := map[string]bool{
		"UpdatedAt": true, // GORM auto-set on Create; defensive, same class as every other Create test in this harness
	}
	assertFieldExhaustiveEqual(t, "RemoteStorage.CreateProjectMembership (response fidelity: wire-returned vs persisted)", remoteCreated, remotePersisted, responseExclude)

	// Duplicate-active-membership conflict (#309): a second create for the SAME
	// (project, user) while a non-revoked membership already exists must be
	// rejected identically on both paths, translating to the SAME sentinel --
	// remote_memberships.go's own CreateProjectMembership doc names this as
	// the exact wire-error-code translation this proxy exists to preserve.
	_, dupLocalErr := h.ls.CreateProjectMembership(ctx, &models.ProjectMembership{
		ProjectID: h.projectID, UserID: localUser.ID, Role: role.Name, State: "invited",
		InvitedBy: h.adminUserID, InvitedAt: invitedAt,
	})
	assert.ErrorIs(t, dupLocalErr, coreStorage.ErrDuplicateActiveMembership,
		"sanity: a second active membership for the same (project, user) must be rejected")

	_, dupRemoteErr := h.rs.CreateProjectMembership(ctx, &models.ProjectMembership{
		ProjectID: h.projectID, UserID: remoteUser.ID, Role: role.Name, State: "invited",
		InvitedBy: forgedInvitedBy, InvitedAt: invitedAt,
	})
	assert.ErrorIs(t, dupRemoteErr, coreStorage.ErrDuplicateActiveMembership,
		"RemoteStorage.CreateProjectMembership must translate the upstream's DB-level duplicate-active-membership "+
			"rejection into the SAME sentinel across the HTTP hop, not an opaque failure")
}

// --- GetProjectMembership ---

func TestConformance_GetProjectMembership(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	user, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-gpm", Email: "conformance-gpm@example.com",
		DisplayName: "Conformance GetProjectMembership", IsActive: true,
	})
	require.NoError(t, err)
	invitedAt := time.Now().UTC().Truncate(time.Second)
	membership, err := h.ls.CreateProjectMembership(ctx, &models.ProjectMembership{
		ProjectID: h.projectID, UserID: user.ID, Role: "system_viewer", State: "invited",
		InvitedBy: h.adminUserID, InvitedAt: invitedAt,
	})
	require.NoError(t, err)

	// ls and rs read the SAME row through the SAME backing store here -- no
	// separate "local"/"remote" fixture needed for a pure read (see the DeleteUser
	// -adjacent skip note above for why that split matters for MUTATING methods).
	viaLocal, err := h.ls.GetProjectMembership(ctx, membership.ID)
	require.NoError(t, err)
	viaRemote, err := h.rs.GetProjectMembership(ctx, membership.ID)
	require.NoError(t, err, "RemoteStorage.GetProjectMembership must find a genuinely existing membership")
	assertFieldExhaustiveEqual(t, "GetProjectMembership (LocalStorage vs RemoteStorage over the SAME row)", viaLocal, viaRemote, nil)

	_, localErr := h.ls.GetProjectMembership(ctx, 999999999)
	_, remoteErr := h.rs.GetProjectMembership(ctx, 999999999)
	assert.Error(t, localErr, "sanity: an unknown membership ID must not resolve")
	assert.Error(t, remoteErr, "RemoteStorage.GetProjectMembership must also refuse an unknown ID, not silently return something")
}

// --- ListProjectMemberships ---

func TestConformance_ListProjectMemberships(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	project, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-lpm-project", "", []string{"dev"})
	require.NoError(t, err)

	newMember := func(suffix, state string) uint {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-lpm-" + suffix, Email: "conformance-lpm-" + suffix + "@example.com",
			DisplayName: "Conformance ListProjectMemberships " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		m, err := h.ls.CreateProjectMembership(ctx, &models.ProjectMembership{
			ProjectID: project.ID, UserID: user.ID, Role: "system_viewer", State: state,
			InvitedBy: h.adminUserID, InvitedAt: time.Now().UTC(),
		})
		require.NoError(t, err)
		return m.ID
	}
	id1 := newMember("a", "invited")
	id2 := newMember("b", "active")

	// A DIFFERENT project's membership must not leak into this project's list
	// -- the scope-drop risk this method exists to catch.
	otherProject, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-lpm-other-project", "", []string{"dev"})
	require.NoError(t, err)
	otherUser, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-lpm-other", Email: "conformance-lpm-other@example.com",
		DisplayName: "Conformance ListProjectMemberships other", IsActive: true,
	})
	require.NoError(t, err)
	_, err = h.ls.CreateProjectMembership(ctx, &models.ProjectMembership{
		ProjectID: otherProject.ID, UserID: otherUser.ID, Role: "system_viewer", State: "invited",
		InvitedBy: h.adminUserID, InvitedAt: time.Now().UTC(),
	})
	require.NoError(t, err)

	viaLocal, err := h.ls.ListProjectMemberships(ctx, project.ID)
	require.NoError(t, err)
	viaRemote, err := h.rs.ListProjectMemberships(ctx, project.ID)
	require.NoError(t, err, "RemoteStorage.ListProjectMemberships must succeed")

	idsOf := func(rows []*models.ProjectMembership) []uint {
		ids := make([]uint, len(rows))
		for i, r := range rows {
			ids[i] = r.ID
		}
		return ids
	}
	assert.ElementsMatch(t, []uint{id1, id2}, idsOf(viaLocal), "sanity: LocalStorage must list exactly this project's memberships")
	assert.ElementsMatch(t, []uint{id1, id2}, idsOf(viaRemote),
		"RemoteStorage.ListProjectMemberships must return exactly the SAME set -- a dropped/wrong project_id on "+
			"the wire would return the wrong project's memberships, or none")
}

// --- GetActiveProjectMembership ---

func TestConformance_GetActiveProjectMembership(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	project, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-gapm-project", "", []string{"dev"})
	require.NoError(t, err)

	activeUser, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-gapm-active", Email: "conformance-gapm-active@example.com",
		DisplayName: "Conformance GetActiveProjectMembership active", IsActive: true,
	})
	require.NoError(t, err)
	active, err := h.ls.CreateProjectMembership(ctx, &models.ProjectMembership{
		ProjectID: project.ID, UserID: activeUser.ID, Role: "system_viewer", State: "active",
		InvitedBy: h.adminUserID, InvitedAt: time.Now().UTC(),
	})
	require.NoError(t, err)

	revokedUser, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-gapm-revoked", Email: "conformance-gapm-revoked@example.com",
		DisplayName: "Conformance GetActiveProjectMembership revoked", IsActive: true,
	})
	require.NoError(t, err)
	_, err = h.ls.CreateProjectMembership(ctx, &models.ProjectMembership{
		ProjectID: project.ID, UserID: revokedUser.ID, Role: "system_viewer", State: "revoked",
		InvitedBy: h.adminUserID, InvitedAt: time.Now().UTC(),
	})
	require.NoError(t, err)

	viaLocal, err := h.ls.GetActiveProjectMembership(ctx, project.ID, activeUser.ID)
	require.NoError(t, err)
	viaRemote, err := h.rs.GetActiveProjectMembership(ctx, project.ID, activeUser.ID)
	require.NoError(t, err, "RemoteStorage.GetActiveProjectMembership must find the genuinely active membership")
	assertFieldExhaustiveEqual(t, "GetActiveProjectMembership (LocalStorage vs RemoteStorage over the SAME row)", viaLocal, viaRemote, nil)
	assert.Equal(t, active.ID, viaRemote.ID)

	// A user whose ONLY membership is revoked must not resolve as active --
	// the state-filter risk this method exists to catch.
	_, localErr := h.ls.GetActiveProjectMembership(ctx, project.ID, revokedUser.ID)
	_, remoteErr := h.rs.GetActiveProjectMembership(ctx, project.ID, revokedUser.ID)
	assert.Error(t, localErr, "sanity: a revoked-only membership must not resolve as active")
	assert.Error(t, remoteErr, "RemoteStorage.GetActiveProjectMembership must also refuse a revoked-only membership, not silently return it")
}

// --- ListStaleInvitedMemberships ---

func TestConformance_ListStaleInvitedMemberships(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	project, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-lsim-project", "", []string{"dev"})
	require.NoError(t, err)

	cutoff := time.Now().UTC()
	stalePast := cutoff.Add(-48 * time.Hour)
	recentFuture := cutoff.Add(48 * time.Hour)

	newMembership := func(suffix, state string, invitedAt time.Time) uint {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-lsim-" + suffix, Email: "conformance-lsim-" + suffix + "@example.com",
			DisplayName: "Conformance ListStaleInvitedMemberships " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		m, err := h.ls.CreateProjectMembership(ctx, &models.ProjectMembership{
			ProjectID: project.ID, UserID: user.ID, Role: "system_viewer", State: state, InvitedBy: h.adminUserID, InvitedAt: invitedAt,
		})
		require.NoError(t, err)
		return m.ID
	}

	staleID := newMembership("stale", "invited", stalePast)
	recentID := newMembership("recent", "invited", recentFuture)
	// Old but NOT invited (already active) -- must be excluded despite the
	// stale invited_at, proving the state filter isn't dropped/widened on the wire.
	activeOldID := newMembership("active-old", "active", stalePast)

	viaLocal, err := h.ls.ListStaleInvitedMemberships(ctx, cutoff)
	require.NoError(t, err)
	viaRemote, err := h.rs.ListStaleInvitedMemberships(ctx, cutoff)
	require.NoError(t, err, "RemoteStorage.ListStaleInvitedMemberships must succeed")

	idsOf := func(rows []*models.ProjectMembership) []uint {
		ids := make([]uint, len(rows))
		for i, r := range rows {
			ids[i] = r.ID
		}
		return ids
	}
	localIDs := idsOf(viaLocal)
	remoteIDs := idsOf(viaRemote)

	assert.Contains(t, localIDs, staleID, "sanity: LocalStorage must list the stale invited membership")
	assert.NotContains(t, localIDs, recentID, "sanity: a recently-invited membership must not be listed as stale")
	assert.NotContains(t, localIDs, activeOldID, "sanity: an old but non-invited membership must not be listed")

	assert.Contains(t, remoteIDs, staleID,
		"RemoteStorage.ListStaleInvitedMemberships must list the stale invited membership -- a dropped/wrong "+
			"'before' cutoff on the wire would omit it")
	assert.NotContains(t, remoteIDs, recentID,
		"RemoteStorage.ListStaleInvitedMemberships must NOT list a recently-invited membership -- a dropped or "+
			"widened cutoff would include it")
	assert.NotContains(t, remoteIDs, activeOldID,
		"RemoteStorage.ListStaleInvitedMemberships must NOT list an old but non-invited membership -- a dropped "+
			"state filter on the wire would include it")
}

// --- ListUserProjectMemberships ---

func TestConformance_ListUserProjectMemberships(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	user, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-lupm", Email: "conformance-lupm@example.com",
		DisplayName: "Conformance ListUserProjectMemberships", IsActive: true,
	})
	require.NoError(t, err)

	projectB, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-lupm-project-b", "", []string{"dev"})
	require.NoError(t, err)

	m1, err := h.ls.CreateProjectMembership(ctx, &models.ProjectMembership{
		ProjectID: h.projectID, UserID: user.ID, Role: "system_viewer", State: "active",
		InvitedBy: h.adminUserID, InvitedAt: time.Now().UTC(),
	})
	require.NoError(t, err)
	m2, err := h.ls.CreateProjectMembership(ctx, &models.ProjectMembership{
		ProjectID: projectB.ID, UserID: user.ID, Role: "system_viewer", State: "invited",
		InvitedBy: h.adminUserID, InvitedAt: time.Now().UTC(),
	})
	require.NoError(t, err)

	// A bystander user's own membership must never appear -- the scope-drop
	// risk this method exists to catch.
	bystander, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-lupm-bystander", Email: "conformance-lupm-bystander@example.com",
		DisplayName: "Conformance ListUserProjectMemberships bystander", IsActive: true,
	})
	require.NoError(t, err)
	_, err = h.ls.CreateProjectMembership(ctx, &models.ProjectMembership{
		ProjectID: h.projectID, UserID: bystander.ID, Role: "system_viewer", State: "active",
		InvitedBy: h.adminUserID, InvitedAt: time.Now().UTC(),
	})
	require.NoError(t, err)

	viaLocal, err := h.ls.ListUserProjectMemberships(ctx, user.ID)
	require.NoError(t, err)
	viaRemote, err := h.rs.ListUserProjectMemberships(ctx, user.ID)
	require.NoError(t, err, "RemoteStorage.ListUserProjectMemberships must succeed")

	idsOf := func(rows []*models.ProjectMembership) []uint {
		ids := make([]uint, len(rows))
		for i, r := range rows {
			ids[i] = r.ID
		}
		return ids
	}
	assert.ElementsMatch(t, []uint{m1.ID, m2.ID}, idsOf(viaLocal), "sanity: LocalStorage must list exactly this user's memberships, across both projects")
	assert.ElementsMatch(t, []uint{m1.ID, m2.ID}, idsOf(viaRemote),
		"RemoteStorage.ListUserProjectMemberships must return exactly the SAME set -- a dropped/wrong user_id on "+
			"the wire would return another user's memberships, or none")
}

// --- CountProjectMembershipsByUsers ---

func TestConformance_CountProjectMembershipsByUsers(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	// uniq_project_memberships_active (#309) allows at most ONE non-revoked
	// membership per (project, user) -- to get a user with Active:1/Total:2,
	// spread the non-revoked memberships across different projects, plus one
	// revoked row (excluded from Total) in a third.
	projectB, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-cpmbu-project-b", "", []string{"dev"})
	require.NoError(t, err)
	projectC, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-cpmbu-project-c", "", []string{"dev"})
	require.NoError(t, err)

	user, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-cpmbu", Email: "conformance-cpmbu@example.com",
		DisplayName: "Conformance CountProjectMembershipsByUsers", IsActive: true,
	})
	require.NoError(t, err)
	for _, tc := range []struct {
		projectID uint
		state     string
	}{
		{h.projectID, "active"},
		{projectB.ID, "invited"},
		{projectC.ID, "revoked"},
	} {
		_, err := h.ls.CreateProjectMembership(ctx, &models.ProjectMembership{
			ProjectID: tc.projectID, UserID: user.ID, Role: "system_viewer", State: tc.state,
			InvitedBy: h.adminUserID, InvitedAt: time.Now().UTC(),
		})
		require.NoError(t, err)
	}

	// A user NOT in the requested ID list must not appear in the result --
	// the scope-drop risk this method exists to catch.
	bystander, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-cpmbu-bystander", Email: "conformance-cpmbu-bystander@example.com",
		DisplayName: "Conformance CountProjectMembershipsByUsers bystander", IsActive: true,
	})
	require.NoError(t, err)
	_, err = h.ls.CreateProjectMembership(ctx, &models.ProjectMembership{
		ProjectID: h.projectID, UserID: bystander.ID, Role: "system_viewer", State: "active",
		InvitedBy: h.adminUserID, InvitedAt: time.Now().UTC(),
	})
	require.NoError(t, err)

	localCounts, err := h.ls.CountProjectMembershipsByUsers(ctx, []uint{user.ID})
	require.NoError(t, err)
	remoteCounts, err := h.rs.CountProjectMembershipsByUsers(ctx, []uint{user.ID})
	require.NoError(t, err, "RemoteStorage.CountProjectMembershipsByUsers must succeed")

	assert.Equal(t, coreStorage.MembershipCounts{Active: 1, Total: 2}, localCounts[user.ID],
		"sanity: one active + one invited (both non-revoked) = active:1 total:2; the revoked row must not count toward total")
	assert.Equal(t, localCounts[user.ID], remoteCounts[user.ID],
		"RemoteStorage.CountProjectMembershipsByUsers must return the identical counts LocalStorage computes over the SAME rows")
	_, bystanderRequested := remoteCounts[bystander.ID]
	assert.False(t, bystanderRequested, "a user ID not in the request must not appear in the result")

	emptyCounts, err := h.rs.CountProjectMembershipsByUsers(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, emptyCounts, "an empty user-ID list must short-circuit to an empty map (RemoteStorage's own shortcut skips the HTTP round trip entirely)")
}

// --- GetSession ---

func TestConformance_GetSession(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	user, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-gs", Email: "conformance-gs@example.com",
		DisplayName: "Conformance GetSession", IsActive: true,
	})
	require.NoError(t, err)

	expiresAt := time.Now().Add(time.Hour).UTC()
	_, err = h.ls.CreateSession(ctx, &models.Session{
		UserID: user.ID, SessionToken: "conformance-gs-token", UserAgent: "conformance-test-agent",
		IPAddress: "127.0.0.1", ExpiresAt: &expiresAt,
	})
	require.NoError(t, err)

	// ls and rs read the SAME session row here -- see GetProjectMembership's
	// comment above for why a pure read doesn't need a separate local/remote fixture.
	viaLocal, err := h.ls.GetSession(ctx, "conformance-gs-token")
	require.NoError(t, err)
	viaRemote, err := h.rs.GetSession(ctx, "conformance-gs-token")
	require.NoError(t, err, "RemoteStorage.GetSession must find a genuinely live session by its token")

	exclude := map[string]bool{
		// models.Session.SessionToken is tagged `json:"-"` BY DESIGN (see
		// remote_auth.go's CreateSession doc comment) -- the at-rest hash must
		// never cross the wire generically, so viaRemote.SessionToken is
		// always "" regardless of viaLocal's real (hashed) value. Analogous to
		// SecretNode.ValueStored's exclusion in tranche 3.
		"SessionToken": true,
	}
	assertFieldExhaustiveEqual(t, "GetSession (LocalStorage vs RemoteStorage over the SAME session)", viaLocal, viaRemote, exclude)
	assert.Empty(t, viaRemote.SessionToken, "sanity: the session hash must never actually cross the wire")

	_, localErr := h.ls.GetSession(ctx, "conformance-gs-nonexistent-token")
	_, remoteErr := h.rs.GetSession(ctx, "conformance-gs-nonexistent-token")
	assert.Error(t, localErr, "sanity: an unknown token must not resolve to a session")
	assert.Error(t, remoteErr, "RemoteStorage.GetSession must also refuse an unknown token, not silently return something")
}

// --- DeleteSession ---

func TestConformance_DeleteSession(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	expiresAt := time.Now().Add(time.Hour).UTC()

	newSession := func(suffix string) *models.Session {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-ds-" + suffix, Email: "conformance-ds-" + suffix + "@example.com",
			DisplayName: "Conformance DeleteSession " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		session, err := h.ls.CreateSession(ctx, &models.Session{
			UserID: user.ID, SessionToken: "conformance-ds-token-" + suffix, ExpiresAt: &expiresAt,
		})
		require.NoError(t, err)
		return session
	}

	localTarget := newSession("local-target")
	localBystander := newSession("local-bystander")
	require.NoError(t, h.ls.DeleteSession(ctx, localTarget.ID))

	remoteTarget := newSession("remote-target")
	remoteBystander := newSession("remote-bystander")
	require.NoError(t, h.rs.DeleteSession(ctx, remoteTarget.ID), "RemoteStorage.DeleteSession must succeed for a genuinely existing session")

	_, localErr := h.ls.GetSessionByID(ctx, localTarget.ID)
	_, remoteErr := h.ls.GetSessionByID(ctx, remoteTarget.ID)
	assert.Error(t, localErr, "sanity: the local target session must be gone")
	assert.Error(t, remoteErr, "the remote target session must actually be gone server-side, not just report success")

	_, bystanderLocalErr := h.ls.GetSessionByID(ctx, localBystander.ID)
	_, bystanderRemoteErr := h.ls.GetSessionByID(ctx, remoteBystander.ID)
	assert.NoError(t, bystanderLocalErr, "sanity: a bystander session must survive")
	assert.NoError(t, bystanderRemoteErr, "a bystander session must survive the remote delete too -- a dropped/wrong ID on the wire would delete the wrong row")

	// Deleting an already-deleted (or never-existent) session ID is a silent
	// no-op on both paths -- GORM's plain Delete-by-ID does not error on zero
	// rows affected. Confirm the wire preserves that exact idempotent
	// semantics rather than turning a harmless double-delete into a surprise error.
	assert.NoError(t, h.ls.DeleteSession(ctx, localTarget.ID))
	assert.NoError(t, h.rs.DeleteSession(ctx, remoteTarget.ID))
}

// --- DeleteSessionsForUserExcept ---

func TestConformance_DeleteSessionsForUserExcept(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	expiresAt := time.Now().Add(time.Hour).UTC()

	newUserWithSessions := func(suffix string, n int) (*models.User, []*models.Session) {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-dsfue-" + suffix, Email: "conformance-dsfue-" + suffix + "@example.com",
			DisplayName: "Conformance DeleteSessionsForUserExcept " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		sessions := make([]*models.Session, 0, n)
		for i := 0; i < n; i++ {
			s, err := h.ls.CreateSession(ctx, &models.Session{
				UserID: user.ID, SessionToken: suffixedToken(suffix, i), ExpiresAt: &expiresAt,
			})
			require.NoError(t, err)
			sessions = append(sessions, s)
		}
		return user, sessions
	}

	// A bystander user's sessions must never be touched -- the scope-drop risk
	// this method exists to catch.
	bystander, bystanderSessions := newUserWithSessions("bystander", 1)

	localUser, localSessions := newUserWithSessions("local", 3)
	exceptID := localSessions[0].ID
	require.NoError(t, h.ls.DeleteSessionsForUserExcept(ctx, localUser.ID, exceptID))
	localRemaining, err := h.ls.ListSessionsByUser(ctx, localUser.ID)
	require.NoError(t, err)
	require.Len(t, localRemaining, 1, "sanity: exactly the excepted session must remain")
	assert.Equal(t, exceptID, localRemaining[0].ID)

	remoteUser, remoteSessions := newUserWithSessions("remote", 3)
	remoteExceptID := remoteSessions[1].ID
	require.NoError(t, h.rs.DeleteSessionsForUserExcept(ctx, remoteUser.ID, remoteExceptID),
		"RemoteStorage.DeleteSessionsForUserExcept must succeed for a genuine target user")
	remoteRemaining, err := h.ls.ListSessionsByUser(ctx, remoteUser.ID)
	require.NoError(t, err)
	// Not zero (over-deleted) and not all (no-op) -- mirroring tranche 3's
	// RemoveAllProjectRoleGrants scoping discipline.
	require.Len(t, remoteRemaining, 1,
		"exactly the excepted session must survive server-side -- not zero and not all")
	assert.Equal(t, remoteExceptID, remoteRemaining[0].ID,
		"the SPECIFIC excepted session ID must be the one that survives, not merely any one session")

	bystanderRemaining, err := h.ls.ListSessionsByUser(ctx, bystander.ID)
	require.NoError(t, err)
	assert.Len(t, bystanderRemaining, len(bystanderSessions), "a bystander user's sessions must survive both calls untouched")
}

// suffixedToken builds a unique session token for DeleteSessionsForUserExcept's
// multi-session fixtures (session_token has a unique index).
func suffixedToken(suffix string, i int) string {
	return "conformance-dsfue-token-" + suffix + "-" + string(rune('a'+i))
}

// --- CreateSetupToken ---

func TestConformance_CreateSetupToken(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newUser := func(suffix string) *models.User {
		user, err := h.ls.CreateUser(ctx, &models.User{
			Username: "conformance-cst-" + suffix, Email: "conformance-cst-" + suffix + "@example.com",
			DisplayName: "Conformance CreateSetupToken " + suffix, IsActive: true,
		})
		require.NoError(t, err)
		return user
	}

	expiresAt := time.Now().Add(24 * time.Hour).UTC()

	localUser := newUser("local")
	localSent := &models.SetupToken{
		TokenHash: "conformance-cst-hash-local", Purpose: "account_setup", SubjectUserID: &localUser.ID,
		SubjectEmail: localUser.Email, State: "active", ExpiresAt: expiresAt, CreatedBy: h.adminUserID,
		CreatedAt: time.Now().UTC(),
	}
	_, err := h.ls.CreateSetupToken(ctx, localSent)
	require.NoError(t, err)
	localPersisted, err := h.ls.GetSetupTokenByHash(ctx, "conformance-cst-hash-local")
	require.NoError(t, err)
	assertFieldExhaustiveEqual(t, "LocalStorage.CreateSetupToken (sanity baseline)", localSent, localPersisted, nil)

	remoteUser := newUser("remote")
	const forgedCreatedBy = 999999
	remoteSent := &models.SetupToken{
		TokenHash: "conformance-cst-hash-remote", Purpose: "account_setup", SubjectUserID: &remoteUser.ID,
		SubjectEmail: remoteUser.Email, State: "active", ExpiresAt: expiresAt, CreatedBy: forgedCreatedBy,
		CreatedAt: time.Now().UTC(),
	}
	remoteCreated, err := h.rs.CreateSetupToken(ctx, remoteSent)
	require.NoError(t, err, "RemoteStorage.CreateSetupToken must succeed for a genuine, matching subject_user_id/subject_email")

	// G80-style forced-attribution check: CreatedBy must come from the
	// authenticated caller server-side, never the wire-supplied value.
	assert.NotEqual(t, uint(forgedCreatedBy), remoteCreated.CreatedBy,
		"CreatedBy must be derived from the authenticated caller server-side, never trusted from the wire")

	remotePersisted, err := h.ls.GetSetupTokenByHash(ctx, "conformance-cst-hash-remote")
	require.NoError(t, err)

	requestExclude := map[string]bool{
		"ID":        true, // not yet assigned on the pre-create wire struct; response fidelity checked separately below
		"CreatedBy": true, // forged input, forced server-side -- asserted explicitly above
		// CONFIRMED WIRE-DROP BUG, not a design choice, NOT fixed in this
		// tranche (see this file's package doc for the full write-up):
		// remote_auth.go's setupTokenWire (RemoteStorage's own client struct)
		// has no CreatedByMachineIdentityID field at all, so it can't even be
		// SENT, let alone round-tripped.
		"CreatedByMachineIdentityID": true,
	}
	assertFieldExhaustiveEqual(t, "RemoteStorage.CreateSetupToken (request fidelity: sent vs persisted)", remoteSent, remotePersisted, requestExclude)

	responseExclude := map[string]bool{
		// Same confirmed bug, RESPONSE side: setup_tokens_proxy.go's
		// setupTokenProxyWire DOES send "created_by_machine_identity_id" (and
		// the server DID correctly derive+persist it from this harness's real
		// machine credential -- see the assert.NotZero below), but
		// remote_auth.go's client-side setupTokenWire has no field to decode
		// it into, so remoteCreated.CreatedByMachineIdentityID always comes
		// back 0 regardless of the true persisted value.
		"CreatedByMachineIdentityID": true,
	}
	assertFieldExhaustiveEqual(t, "RemoteStorage.CreateSetupToken (response fidelity: wire-returned vs persisted)", remoteCreated, remotePersisted, responseExclude)

	assert.NotZero(t, remotePersisted.CreatedByMachineIdentityID,
		"sanity: the server-side create really did derive and persist real machine attribution from the "+
			"authenticated node credential -- confirms the gap documented above is a client-side wire-decode "+
			"drop only, not a full server-side loss of attribution too")

	// Cross-reference guard: CreateSetupTokenProxy rejects a subject_user_id/
	// subject_email pair that doesn't reference the same real user -- a
	// wire-fidelity guard unreachable on the raw LocalStorage primitive (which
	// performs no such check), so there is no local-side equivalent to assert here.
	_, err = h.rs.CreateSetupToken(ctx, &models.SetupToken{
		TokenHash: "conformance-cst-hash-mismatch", Purpose: "account_setup", SubjectUserID: &remoteUser.ID,
		SubjectEmail: "conformance-cst-mismatched-email@example.com", State: "active", ExpiresAt: expiresAt,
	})
	assert.Error(t, err, "RemoteStorage.CreateSetupToken must refuse a subject_user_id/subject_email pair that "+
		"does not cross-reference the same real user")
}

// --- GetSetupTokenByHash ---

func TestConformance_GetSetupTokenByHash(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	user, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-gsth", Email: "conformance-gsth@example.com",
		DisplayName: "Conformance GetSetupTokenByHash", IsActive: true,
	})
	require.NoError(t, err)

	_, err = h.ls.CreateSetupToken(ctx, &models.SetupToken{
		TokenHash: "conformance-gsth-hash", Purpose: "account_setup", SubjectUserID: &user.ID,
		SubjectEmail: user.Email, State: "active", ExpiresAt: time.Now().Add(24 * time.Hour).UTC(),
		CreatedBy: h.adminUserID, CreatedAt: time.Now().UTC(),
	})
	require.NoError(t, err)

	viaLocal, err := h.ls.GetSetupTokenByHash(ctx, "conformance-gsth-hash")
	require.NoError(t, err)
	viaRemote, err := h.rs.GetSetupTokenByHash(ctx, "conformance-gsth-hash")
	require.NoError(t, err, "RemoteStorage.GetSetupTokenByHash must find a genuinely active token by hash")
	assertFieldExhaustiveEqual(t, "GetSetupTokenByHash (LocalStorage vs RemoteStorage over the SAME row)", viaLocal, viaRemote, nil)

	_, localErr := h.ls.GetSetupTokenByHash(ctx, "conformance-gsth-nonexistent")
	_, remoteErr := h.rs.GetSetupTokenByHash(ctx, "conformance-gsth-nonexistent")
	assert.Error(t, localErr, "sanity: an unknown hash must not resolve")
	assert.Error(t, remoteErr, "RemoteStorage.GetSetupTokenByHash must also refuse an unknown hash, not silently return something")
}

// --- MarkSetupTokenExpired ---

func TestConformance_MarkSetupTokenExpired(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newActiveToken := func(hash string) *models.SetupToken {
		tok, err := h.ls.CreateSetupToken(ctx, &models.SetupToken{
			TokenHash: hash, Purpose: "account_setup", SubjectEmail: "conformance-mste@example.com",
			State: "active", ExpiresAt: time.Now().Add(24 * time.Hour).UTC(), CreatedAt: time.Now().UTC(),
		})
		require.NoError(t, err)
		return tok
	}

	localTok := newActiveToken("conformance-mste-local")
	require.NoError(t, h.ls.MarkSetupTokenExpired(ctx, localTok.ID))
	localAfter, err := h.ls.GetSetupTokenByHash(ctx, "conformance-mste-local")
	require.NoError(t, err)
	assert.Equal(t, "expired", localAfter.State, "sanity: local expire must flip active -> expired")

	remoteTok := newActiveToken("conformance-mste-remote")
	require.NoError(t, h.rs.MarkSetupTokenExpired(ctx, remoteTok.ID),
		"RemoteStorage.MarkSetupTokenExpired must succeed for a genuinely active token")
	remoteAfter, err := h.ls.GetSetupTokenByHash(ctx, "conformance-mste-remote")
	require.NoError(t, err)
	assert.Equal(t, "expired", remoteAfter.State, "the remote token must actually be expired server-side, not just report success")

	// Expiring an ALREADY-expired token is a silent no-op on both paths (the
	// underlying `WHERE state = 'active'` UPDATE matches zero rows, and
	// local_auth.go's MarkSetupTokenExpired does not check RowsAffected) --
	// confirm the wire preserves that exact idempotent semantics rather than
	// turning a harmless re-expire into a surprise error.
	require.NoError(t, h.ls.MarkSetupTokenExpired(ctx, localTok.ID))
	require.NoError(t, h.rs.MarkSetupTokenExpired(ctx, remoteTok.ID))
	localStill, err := h.ls.GetSetupTokenByHash(ctx, "conformance-mste-local")
	require.NoError(t, err)
	remoteStill, err := h.ls.GetSetupTokenByHash(ctx, "conformance-mste-remote")
	require.NoError(t, err)
	assert.Equal(t, "expired", localStill.State)
	assert.Equal(t, "expired", remoteStill.State)
}

// --- SupersedeActiveSetupTokens ---

func TestConformance_SupersedeActiveSetupTokens(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newActiveToken := func(email, hash string) {
		_, err := h.ls.CreateSetupToken(ctx, &models.SetupToken{
			TokenHash: hash, Purpose: "password_reset_link", SubjectEmail: email,
			State: "active", ExpiresAt: time.Now().Add(24 * time.Hour).UTC(), CreatedAt: time.Now().UTC(),
		})
		require.NoError(t, err)
	}

	const localEmail = "conformance-sast-local@example.com"
	const localBystanderEmail = "conformance-sast-local-bystander@example.com"
	newActiveToken(localEmail, "conformance-sast-local-1")
	newActiveToken(localEmail, "conformance-sast-local-2")
	newActiveToken(localBystanderEmail, "conformance-sast-local-bystander")
	require.NoError(t, h.ls.SupersedeActiveSetupTokens(ctx, "password_reset_link", localEmail, nil))

	tok1, err := h.ls.GetSetupTokenByHash(ctx, "conformance-sast-local-1")
	require.NoError(t, err)
	tok2, err := h.ls.GetSetupTokenByHash(ctx, "conformance-sast-local-2")
	require.NoError(t, err)
	localBystanderTok, err := h.ls.GetSetupTokenByHash(ctx, "conformance-sast-local-bystander")
	require.NoError(t, err)
	assert.Equal(t, "superseded", tok1.State, "sanity: both same-email active tokens must be superseded")
	assert.Equal(t, "superseded", tok2.State)
	assert.Equal(t, "active", localBystanderTok.State, "sanity: a different email's active token must survive")

	const remoteEmail = "conformance-sast-remote@example.com"
	const remoteBystanderEmail = "conformance-sast-remote-bystander@example.com"
	newActiveToken(remoteEmail, "conformance-sast-remote-1")
	newActiveToken(remoteEmail, "conformance-sast-remote-2")
	newActiveToken(remoteBystanderEmail, "conformance-sast-remote-bystander")
	require.NoError(t, h.rs.SupersedeActiveSetupTokens(ctx, "password_reset_link", remoteEmail, nil),
		"RemoteStorage.SupersedeActiveSetupTokens must succeed")

	rtok1, err := h.ls.GetSetupTokenByHash(ctx, "conformance-sast-remote-1")
	require.NoError(t, err)
	rtok2, err := h.ls.GetSetupTokenByHash(ctx, "conformance-sast-remote-2")
	require.NoError(t, err)
	remoteBystanderTok, err := h.ls.GetSetupTokenByHash(ctx, "conformance-sast-remote-bystander")
	require.NoError(t, err)
	assert.Equal(t, "superseded", rtok1.State, "both of the remote email's active tokens must actually be superseded server-side")
	assert.Equal(t, "superseded", rtok2.State)
	assert.Equal(t, "active", remoteBystanderTok.State,
		"a different email's active token must survive the remote call too -- a dropped/widened email filter on "+
			"the wire would supersede it too")

	// Already-superseded: calling again for the same (purpose, email) matches
	// zero rows (no more active tokens left) and is a silent no-op, not an
	// error, on both paths.
	require.NoError(t, h.ls.SupersedeActiveSetupTokens(ctx, "password_reset_link", localEmail, nil))
	require.NoError(t, h.rs.SupersedeActiveSetupTokens(ctx, "password_reset_link", remoteEmail, nil))
}

// --- CountSetupTokensSince ---

func TestConformance_CountSetupTokensSince(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	const purpose = "account_setup"
	const email = "conformance-csts@example.com"
	cutoff := time.Now().UTC()
	before := cutoff.Add(-time.Hour)
	after1 := cutoff.Add(time.Hour)
	after2 := cutoff.Add(2 * time.Hour)

	newToken := func(hash string, createdAt time.Time, tokenEmail string) {
		_, err := h.ls.CreateSetupToken(ctx, &models.SetupToken{
			TokenHash: hash, Purpose: purpose, SubjectEmail: tokenEmail, State: "active",
			ExpiresAt: createdAt.Add(24 * time.Hour), CreatedAt: createdAt,
		})
		require.NoError(t, err)
	}
	newToken("conformance-csts-before", before, email)
	newToken("conformance-csts-after-1", after1, email)
	newToken("conformance-csts-after-2", after2, email)
	// A different email must not be counted -- scope check.
	newToken("conformance-csts-other-email", after1, "conformance-csts-other@example.com")

	localCount, err := h.ls.CountSetupTokensSince(ctx, purpose, email, cutoff)
	require.NoError(t, err)
	remoteCount, err := h.rs.CountSetupTokensSince(ctx, purpose, email, cutoff)
	require.NoError(t, err, "RemoteStorage.CountSetupTokensSince must succeed")

	assert.Equal(t, int64(2), localCount, "sanity: only the two after-cutoff, same-email tokens must count")
	assert.Equal(t, localCount, remoteCount,
		"RemoteStorage.CountSetupTokensSince must return the identical count LocalStorage computes over the SAME rows")
}

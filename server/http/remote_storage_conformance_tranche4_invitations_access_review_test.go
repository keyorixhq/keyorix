// remote_storage_conformance_tranche4_invitations_access_review_test.go —
// issue #1808, tranche 4.
//
// Scope: all 20 real *RemoteStorage methods backed by
// internal/storage/store/remote_invitations.go (project invitations + access
// requests, ADR-024/#523) and internal/storage/store/remote_access_review_campaigns.go
// (access-review campaigns, ISO 27001 A.5.18, #519) — every method named in
// this tranche's assignment is covered; none skipped.
//
//	remote_invitations.go: CreateAccessRequest, CreateAccessRequestApproval,
//	CreateProjectInvitation, GetAccessRequest, GetProjectInvitation,
//	ListAccessRequestApprovals, ListAccessRequests, ListProjectInvitations,
//	UpdateAccessRequest, UpdateProjectInvitation
//
//	remote_access_review_campaigns.go: CountPendingAccessReviewItems,
//	CreateAccessReviewCampaign, CreateAccessReviewItems,
//	GetAccessReviewCampaign, GetAccessReviewItem,
//	GetLatestClosedAccessReviewCampaign, GetOpenAccessReviewCampaign,
//	ListAccessReviewCampaigns, ListAccessReviewItems, UpdateAccessReviewItem
//
// (UpdateAccessReviewCampaign, also in that file, is deliberately excluded —
// it was deleted in the G80 liveness sweep and now always returns
// errUnsupportedRemote; it is not in this tranche's method list.)
//
// # Actor-identity gating discovered while writing this tranche
//
// Several of these routes gate on the AUTHENTICATED caller's actor kind, not
// just a permission bit, which shapes which harness credential can drive each
// test:
//
//   - actorID(r) (server/http/handlers/catalog.go) always returns 0 for a
//     machine/node caller (UserContext.UserID is never set for one) — so
//     CreateInvitationProxy's InvitedBy and CreateAccessReviewCampaignProxy's
//     CreatedBy always land as 0 when created via h.rs (the harness's
//     node/machine credential), never the caller's real identity.
//   - requestActorKindAndID(r), used by the access-request routes, DOES carry
//     a machine caller's real PrincipalID (unlike actorID) — AccessRequest's
//     ResolvedByMachineIdentityID / AccessRequestApproval's
//     ApproverMachineIdentityID correctly capture it (the #1573/#1622 fix).
//   - RequireGranterHoldsRolePermissions unconditionally refuses ANY
//     permission-carrying role grant for a machine actor relayed through a
//     /system proxy route with no WithSelfMachineGranter tag (no such tag is
//     ever set on this tree) — confirmed in tranche 3's AssignRoleWithExpiry/
//     AssignMachineRole comment; every role created below for a
//     CreateInvitationProxy/UpdateAccessRequestProxy/
//     CreateAccessRequestApprovalProxy call is a zero-permission role for the
//     same reason (the loop that does the refusing has nothing to iterate).
//   - RequireAdminAuthorityAt is a USER-scoped check only (scopedRoleIDs never
//     consults machine role grants) — a secret-scoped access-request approval
//     is therefore only reachable by a real user session, not h.rs; this
//     tranche exercises the project/role-scoped approve branch instead (which
//     RequireGranterHoldsRolePermissions gates, satisfiable by a
//     zero-permission role) rather than adding a second minted user session
//     for a branch that would exercise the same wire-fidelity contract twice.
//   - AuthorizePrincipal for a machine actor has NO admin-name bypass
//     (internal/core/authz.go's own doc comment) — h.rs's "roles.assign" pass
//     for UpdateAccessRequestProxy's reject/expire branch works because the
//     admin role's own permission bundle genuinely includes "roles.assign" at
//     global scope (which GetMachineRoleIDsAt's project_id=0 OR project_id=?
//     clause matches against any project), not because of a bypass.
//   - UpdateAccessReviewItemProxy hard-refuses any non-human caller outright
//     (ARC-005: "an independent reviewer concept has no meaning for a machine
//     caller") — h.rs cannot drive this route at all, so
//     TestConformance_UpdateAccessReviewItem mints a second RemoteStorage
//     client on a real user session, mirroring tranche 3's
//     RevokeBreakGlassActivation.
//
// # Two known wire-fidelity gaps found while writing this tranche
//
// Neither is fixed here ("Do NOT modify any existing file" — this tranche's
// assignment) — both are flagged as follow-up findings, asserted as the
// CURRENT (unfortunate) behavior rather than silently excluded from
// comparison, so a future fix has a red test to turn green:
//
//  1. models.ProjectInvitation.InvitedByMachineIdentityID (#1573) exists
//     specifically so a machine caller's real identity survives when
//     InvitedBy is 0 for that reason — the same fix already applied to
//     AccessRequest.ResolvedByMachineIdentityID / AccessRequestApproval.
//     ApproverMachineIdentityID. Neither invitationWire
//     (remote_invitations.go) nor invitationProxyWire (invitations_proxy.go)
//     carries this field, and CreateInvitationProxy never independently sets
//     it — an invitation genuinely created by a machine/node credential (the
//     realistic production caller for this storage-layer method, per this
//     file's own package doc) silently loses its inviter's identity
//     entirely. See TestConformance_CreateProjectInvitation.
//  2. models.AccessReviewCampaign.CreatedByMachineIdentityID/
//     ClosedByMachineIdentityID (#1573) have the identical gap: absent from
//     accessReviewCampaignWire/accessReviewCampaignProxyWire, never
//     independently set by CreateAccessReviewCampaignProxy. See
//     TestConformance_CreateAccessReviewCampaign.
package http

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// --- CreateProjectInvitation ---

func TestConformance_CreateProjectInvitation(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	// A zero-permission role for the invitation's Role field -- see this
	// file's package doc on RequireGranterHoldsRolePermissions.
	roleName, err := identity.NewFoldedName("conformance-cpi-role")
	require.NoError(t, err)
	role, err := h.ls.CreateRole(ctx, roleName, "conformance test role")
	require.NoError(t, err)

	expiresAt := time.Now().Add(72 * time.Hour).UTC()

	// Local sanity baseline: LocalStorage.CreateProjectInvitation is a raw
	// create -- every field, including InvitedBy, round-trips verbatim.
	localInput := &models.ProjectInvitation{
		ProjectID: h.projectID, Email: "conformance-cpi-local@example.com", Role: role.Name,
		State: "pending", InvitedBy: h.adminUserID, ValidationModeAtInvite: "strict", ExpiresAt: &expiresAt,
	}
	localCreated, err := h.ls.CreateProjectInvitation(ctx, localInput)
	require.NoError(t, err)
	localPersisted, err := h.ls.GetProjectInvitation(ctx, localCreated.ID)
	require.NoError(t, err)
	assertFieldExhaustiveEqual(t, "LocalStorage.CreateProjectInvitation (sanity baseline)", localInput, localPersisted,
		map[string]bool{"ID": true, "CreatedAt": true})

	// Remote: CreateInvitationProxy forces InvitedBy to the AUTHENTICATED
	// caller, never the wire value (2026-08-25 finding, invitations_proxy.go's
	// own package doc) -- the harness's machine/node credential's actorID(r)
	// is always 0, so InvitedBy lands as 0, not the forged admin ID below.
	const forgedInvitedBy = 999999
	remoteInput := &models.ProjectInvitation{
		ProjectID: h.projectID, Email: "conformance-cpi-remote@example.com", Role: role.Name,
		State: "pending", InvitedBy: forgedInvitedBy, ValidationModeAtInvite: "strict", ExpiresAt: &expiresAt,
	}
	remoteCreated, err := h.rs.CreateProjectInvitation(ctx, remoteInput)
	require.NoError(t, err, "RemoteStorage.CreateProjectInvitation must succeed for a zero-permission role")
	remotePersisted, err := h.ls.GetProjectInvitation(ctx, remoteCreated.ID)
	require.NoError(t, err)
	assert.NotEqual(t, uint(forgedInvitedBy), remotePersisted.InvitedBy,
		"InvitedBy must be derived from the authenticated caller, never trusted from the wire")
	assert.Equal(t, uint(0), remotePersisted.InvitedBy,
		"the harness's machine/node credential's actorID(r) is always 0 (no UserID) -- InvitedBy lands as 0")

	// KNOWN WIRE-FIDELITY GAP -- see this file's package doc, item 1. Asserting
	// the CURRENT (unfortunate) behavior rather than excluding the field
	// silently.
	assert.Equal(t, uint(0), remotePersisted.InvitedByMachineIdentityID,
		"KNOWN GAP: the machine caller's real identity is silently lost -- InvitedByMachineIdentityID is not "+
			"carried on this wire at all today (see this file's package doc)")

	assertFieldExhaustiveEqual(t, "RemoteStorage.CreateProjectInvitation (wire round trip, InvitedBy* excluded -- see comments)",
		remoteInput, remotePersisted,
		map[string]bool{"ID": true, "CreatedAt": true, "InvitedBy": true, "InvitedByMachineIdentityID": true})
}

// --- GetProjectInvitation ---

func TestConformance_GetProjectInvitation(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()
	expiresAt := time.Now().Add(48 * time.Hour).UTC()

	inv, err := h.ls.CreateProjectInvitation(ctx, &models.ProjectInvitation{
		ProjectID: h.projectID, Email: "conformance-gpi@example.com", Role: "irrelevant-role-name",
		State: "pending", InvitedBy: h.adminUserID, ValidationModeAtInvite: "strict", ExpiresAt: &expiresAt,
	})
	require.NoError(t, err)

	localFound, err := h.ls.GetProjectInvitation(ctx, inv.ID)
	require.NoError(t, err)
	remoteFound, err := h.rs.GetProjectInvitation(ctx, inv.ID)
	require.NoError(t, err, "RemoteStorage.GetProjectInvitation must find an invitation that genuinely exists")
	assertFieldExhaustiveEqual(t, "GetProjectInvitation", localFound, remoteFound, nil)

	_, localErr := h.ls.GetProjectInvitation(ctx, inv.ID+999999)
	_, remoteErr := h.rs.GetProjectInvitation(ctx, inv.ID+999999)
	assert.Error(t, localErr, "sanity: a nonexistent invitation ID must error locally")
	assert.Error(t, remoteErr, "RemoteStorage.GetProjectInvitation must error for a nonexistent invitation ID")
}

// --- UpdateProjectInvitation ---

func TestConformance_UpdateProjectInvitation(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newPendingInvitation := func(suffix string) *models.ProjectInvitation {
		inv, err := h.ls.CreateProjectInvitation(ctx, &models.ProjectInvitation{
			ProjectID: h.projectID, Email: "conformance-upi-" + suffix + "@example.com",
			Role: "conformance-upi-role-" + suffix, State: "pending", InvitedBy: h.adminUserID,
			SystemRole: "conformance-upi-sysrole-" + suffix,
		})
		require.NoError(t, err)
		return inv
	}

	acceptedAt := time.Now().UTC()
	revokedAt := time.Now().UTC()

	// Wrong-fromState precondition + sanity baseline: LocalStorage.UpdateProjectInvitation
	// is a raw Select("*") full-row update with no re-fetch/narrowing of its
	// own (unlike the proxy handler below) -- a real caller mutates the FULL
	// row it already fetched, which is exactly what this does.
	localInv := newPendingInvitation("local")
	localInv.State = "accepted"
	localInv.AcceptedAt = &acceptedAt
	localMatched, err := h.ls.UpdateProjectInvitation(ctx, localInv)
	require.NoError(t, err)
	require.True(t, localMatched, "sanity: the first transition off pending must match")
	localInv.State = "revoked"
	localInv.RevokedAt = &revokedAt
	localMatchedAgain, err := h.ls.UpdateProjectInvitation(ctx, localInv)
	require.NoError(t, err)
	assert.False(t, localMatchedAgain, "sanity: a second transition off an already-resolved invitation must not match")

	// Remote: UpdateInvitationProxy re-fetches the authoritative row
	// server-side and applies ONLY State/AcceptedAt/RevokedAt from the wire
	// onto it -- a forged Role/SystemRole/Email/InvitedBy in the wire body
	// must NOT overwrite the original row's identity, even though the
	// underlying storage call is a Select("*") full-row update (the
	// AR-001-shape guard, invitations_proxy.go's own package doc).
	remoteInv := newPendingInvitation("remote")
	remoteMatched, err := h.rs.UpdateProjectInvitation(ctx, &models.ProjectInvitation{
		ID: remoteInv.ID, State: "accepted", AcceptedAt: &acceptedAt,
		Role: "forged-role", SystemRole: "forged-sysrole", Email: "forged@evil.example", InvitedBy: 999999,
	})
	require.NoError(t, err, "RemoteStorage.UpdateProjectInvitation must match a genuinely pending invitation")
	require.True(t, remoteMatched)
	afterFirst, err := h.ls.GetProjectInvitation(ctx, remoteInv.ID)
	require.NoError(t, err)
	assert.Equal(t, "accepted", afterFirst.State)
	require.NotNil(t, afterFirst.AcceptedAt)
	assert.True(t, afterFirst.AcceptedAt.Equal(acceptedAt))
	assert.Equal(t, remoteInv.Role, afterFirst.Role, "a forged Role on the wire must not overwrite the original")
	assert.Equal(t, remoteInv.SystemRole, afterFirst.SystemRole, "a forged SystemRole on the wire must not overwrite the original")
	assert.Equal(t, remoteInv.Email, afterFirst.Email, "a forged Email on the wire must not overwrite the original")
	assert.Equal(t, remoteInv.InvitedBy, afterFirst.InvitedBy, "a forged InvitedBy on the wire must not overwrite the original")

	remoteMatchedAgain, err := h.rs.UpdateProjectInvitation(ctx, &models.ProjectInvitation{ID: remoteInv.ID, State: "revoked", RevokedAt: &revokedAt})
	require.NoError(t, err)
	assert.False(t, remoteMatchedAgain,
		"RemoteStorage.UpdateProjectInvitation must report no match for a second transition attempt off an "+
			"already-resolved invitation, not silently re-apply it")
	afterSecond, err := h.ls.GetProjectInvitation(ctx, remoteInv.ID)
	require.NoError(t, err)
	assert.Equal(t, "accepted", afterSecond.State, "the failed second transition attempt must not have altered the row's state")
}

// --- ListProjectInvitations ---

func TestConformance_ListProjectInvitations(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	inv1, err := h.ls.CreateProjectInvitation(ctx, &models.ProjectInvitation{
		ProjectID: h.projectID, Email: "conformance-lpi-1@example.com", Role: "irrelevant-role-name",
		State: "pending", InvitedBy: h.adminUserID,
	})
	require.NoError(t, err)
	inv2, err := h.ls.CreateProjectInvitation(ctx, &models.ProjectInvitation{
		ProjectID: h.projectID, Email: "conformance-lpi-2@example.com", Role: "irrelevant-role-name",
		State: "revoked", InvitedBy: h.adminUserID,
	})
	require.NoError(t, err)
	_, _ = inv1, inv2

	localRows, err := h.ls.ListProjectInvitations(ctx, h.projectID)
	require.NoError(t, err)
	remoteRows, err := h.rs.ListProjectInvitations(ctx, h.projectID)
	require.NoError(t, err, "RemoteStorage.ListProjectInvitations must list the SAME invitations server-side")
	require.Len(t, remoteRows, len(localRows))
	require.GreaterOrEqual(t, len(localRows), 2)
	localByID := map[uint]*models.ProjectInvitation{}
	for _, inv := range localRows {
		localByID[inv.ID] = inv
	}
	for _, rinv := range remoteRows {
		linv, ok := localByID[rinv.ID]
		require.True(t, ok, "remote row %d has no matching local row", rinv.ID)
		assertFieldExhaustiveEqual(t, fmt.Sprintf("ListProjectInvitations invitation %d", rinv.ID), linv, rinv, nil)
	}

	// Negative: a fresh project with zero invitations must return an empty list.
	otherProject, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-lpi-other-project", "", []string{"dev"})
	require.NoError(t, err)
	emptyLocal, err := h.ls.ListProjectInvitations(ctx, otherProject.ID)
	require.NoError(t, err)
	assert.Empty(t, emptyLocal)
	emptyRemote, err := h.rs.ListProjectInvitations(ctx, otherProject.ID)
	require.NoError(t, err)
	assert.Empty(t, emptyRemote, "RemoteStorage.ListProjectInvitations must return an empty list for a project with no invitations")
}

// --- CreateAccessRequest ---

func TestConformance_CreateAccessRequest(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	requester, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-car-requester", Email: "conformance-car-requester@example.com",
		DisplayName: "Conformance CreateAccessRequest Requester", IsActive: true,
	})
	require.NoError(t, err)
	expiresAt := time.Now().Add(24 * time.Hour).UTC()

	// Local sanity baseline: LocalStorage.CreateAccessRequest is a raw create
	// -- every field, including ResolvedBy, round-trips verbatim.
	localInput := &models.AccessRequest{
		ProjectID: h.projectID, UserID: requester.ID, SuggestedRole: "conformance-role",
		State: core.AccessRequestPending, Reason: "conformance local", ExpiresAt: &expiresAt, ResolvedBy: h.adminUserID,
	}
	localCreated, err := h.ls.CreateAccessRequest(ctx, localInput)
	require.NoError(t, err)
	localPersisted, err := h.ls.GetAccessRequest(ctx, localCreated.ID)
	require.NoError(t, err)
	assertFieldExhaustiveEqual(t, "LocalStorage.CreateAccessRequest (sanity baseline)", localInput, localPersisted,
		map[string]bool{"ID": true, "CreatedAt": true})

	// Remote: CreateAccessRequestProxy always forces ResolvedBy to 0 on create
	// (#1529-shape guard, access_request_proxy.go's own package doc) -- a
	// newly created request is never pre-resolved, regardless of the wire.
	const forgedResolvedBy = 999999
	remoteInput := &models.AccessRequest{
		ProjectID: h.projectID, UserID: requester.ID, SuggestedRole: "conformance-role",
		State: core.AccessRequestPending, Reason: "conformance remote", ExpiresAt: &expiresAt, ResolvedBy: forgedResolvedBy,
	}
	remoteCreated, err := h.rs.CreateAccessRequest(ctx, remoteInput)
	require.NoError(t, err, "RemoteStorage.CreateAccessRequest must succeed for a well-formed pending request")
	remotePersisted, err := h.ls.GetAccessRequest(ctx, remoteCreated.ID)
	require.NoError(t, err)
	assert.Equal(t, uint(0), remotePersisted.ResolvedBy, "ResolvedBy must be forced to 0 on create regardless of the wire value")
	assertFieldExhaustiveEqual(t, "RemoteStorage.CreateAccessRequest (wire round trip)", remoteInput, remotePersisted,
		map[string]bool{"ID": true, "CreatedAt": true, "ResolvedBy": true})

	// Negative: CreateAccessRequestProxy's own #1529-shape guard rejects any
	// State other than "pending" outright -- a caller cannot mint a
	// pre-resolved request via this route.
	_, err = h.rs.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: h.projectID, UserID: requester.ID, SuggestedRole: "conformance-role", State: core.AccessRequestApproved,
	})
	assert.Error(t, err, "RemoteStorage.CreateAccessRequest must refuse a request created in a non-pending state")
}

// --- GetAccessRequest ---

func TestConformance_GetAccessRequest(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	requester, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-gar-requester", Email: "conformance-gar-requester@example.com",
		DisplayName: "Conformance GetAccessRequest Requester", IsActive: true,
	})
	require.NoError(t, err)
	req, err := h.ls.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: h.projectID, UserID: requester.ID, SuggestedRole: "conformance-role", State: core.AccessRequestPending,
	})
	require.NoError(t, err)

	localFound, err := h.ls.GetAccessRequest(ctx, req.ID)
	require.NoError(t, err)
	remoteFound, err := h.rs.GetAccessRequest(ctx, req.ID)
	require.NoError(t, err, "RemoteStorage.GetAccessRequest must find a request that genuinely exists")
	assertFieldExhaustiveEqual(t, "GetAccessRequest", localFound, remoteFound, nil)

	_, localErr := h.ls.GetAccessRequest(ctx, req.ID+999999)
	_, remoteErr := h.rs.GetAccessRequest(ctx, req.ID+999999)
	assert.Error(t, localErr, "sanity: a nonexistent access-request ID must error locally")
	assert.Error(t, remoteErr, "RemoteStorage.GetAccessRequest must error for a nonexistent request ID")
}

// --- UpdateAccessRequest ---

func TestConformance_UpdateAccessRequest(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	roleName, err := identity.NewFoldedName("conformance-uar-role")
	require.NoError(t, err)
	role, err := h.ls.CreateRole(ctx, roleName, "conformance test role")
	require.NoError(t, err)

	requester, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-uar-requester", Email: "conformance-uar-requester@example.com",
		DisplayName: "Conformance UpdateAccessRequest Requester", IsActive: true,
	})
	require.NoError(t, err)

	newPendingRequest := func(suffix string) *models.AccessRequest {
		req, err := h.ls.CreateAccessRequest(ctx, &models.AccessRequest{
			ProjectID: h.projectID, UserID: requester.ID, SuggestedRole: role.Name,
			State: core.AccessRequestPending, Reason: "conformance test " + suffix,
		})
		require.NoError(t, err)
		return req
	}

	// Wrong-fromState precondition + sanity baseline: LocalStorage.UpdateAccessRequest
	// is a raw Select("*") full-row update -- a real caller mutates the full
	// row it already fetched, which is exactly what this does.
	localReq := newPendingRequest("local")
	localReq.State = core.AccessRequestRejected
	localReq.GrantedRole = role.Name
	localMatched, err := h.ls.UpdateAccessRequest(ctx, localReq)
	require.NoError(t, err)
	require.True(t, localMatched, "sanity: the first transition off pending must match")
	localReq.State = core.AccessRequestApproved
	localMatchedAgain, err := h.ls.UpdateAccessRequest(ctx, localReq)
	require.NoError(t, err)
	assert.False(t, localMatchedAgain, "sanity: a second transition off an already-resolved request must not match")

	// Remote, reject branch: AuthorizePrincipal(machine, "roles.assign", scope)
	// -- see this file's package doc for why this passes for h.rs (a real held
	// permission via the admin role's own bundle, not a bypass).
	rejectReq := newPendingRequest("reject")
	rejectMatched, err := h.rs.UpdateAccessRequest(ctx, &models.AccessRequest{
		ID: rejectReq.ID, ProjectID: rejectReq.ProjectID, UserID: rejectReq.UserID,
		SuggestedRole: rejectReq.SuggestedRole, State: core.AccessRequestRejected, Reason: "conformance reject",
	})
	require.NoError(t, err, "RemoteStorage.UpdateAccessRequest must match a genuinely pending request for a roles.assign holder")
	require.True(t, rejectMatched)
	afterReject, err := h.ls.GetAccessRequest(ctx, rejectReq.ID)
	require.NoError(t, err)
	assert.Equal(t, core.AccessRequestRejected, afterReject.State)
	assert.Equal(t, "conformance reject", afterReject.Reason, "Reason must round-trip correctly")

	rejectMatchedAgain, err := h.rs.UpdateAccessRequest(ctx, &models.AccessRequest{
		ID: rejectReq.ID, ProjectID: rejectReq.ProjectID, UserID: rejectReq.UserID,
		SuggestedRole: rejectReq.SuggestedRole, State: core.AccessRequestApproved,
	})
	require.NoError(t, err)
	assert.False(t, rejectMatchedAgain,
		"RemoteStorage.UpdateAccessRequest must report no match for a second transition attempt off an "+
			"already-resolved request, not silently re-apply it")
	afterSecond, err := h.ls.GetAccessRequest(ctx, rejectReq.ID)
	require.NoError(t, err)
	assert.Equal(t, core.AccessRequestRejected, afterSecond.State, "the failed second transition attempt must not have altered the row's state")

	// Remote, approve branch (project/role-scoped, zero-permission role) --
	// forged resolved_by on the wire must be discarded: UpdateAccessRequestProxy
	// always derives attribution from the AUTHENTICATED caller. For a machine
	// actor, the real attribution lands in ResolvedByMachineIdentityID (the
	// #1573/#1622-fixed sibling field for THIS model -- unlike
	// ProjectInvitation/AccessReviewCampaign's still-missing sibling, flagged
	// in this file's package doc), never in ResolvedBy and never trusting the
	// wire value for either.
	const forgedResolvedBy = 999999
	now := time.Now().UTC()
	approveReq := newPendingRequest("approve")
	approveMatched, err := h.rs.UpdateAccessRequest(ctx, &models.AccessRequest{
		ID: approveReq.ID, ProjectID: approveReq.ProjectID, UserID: approveReq.UserID,
		SuggestedRole: approveReq.SuggestedRole, GrantedRole: role.Name,
		State: core.AccessRequestApproved, ResolvedBy: forgedResolvedBy, ResolvedAt: &now,
	})
	require.NoError(t, err, "RemoteStorage.UpdateAccessRequest must match a genuinely pending request for a zero-permission role grant")
	require.True(t, approveMatched)
	persisted, err := h.ls.GetAccessRequest(ctx, approveReq.ID)
	require.NoError(t, err)
	assert.Equal(t, core.AccessRequestApproved, persisted.State)
	assert.Equal(t, role.Name, persisted.GrantedRole, "GrantedRole must round-trip correctly")
	assert.NotEqual(t, uint(forgedResolvedBy), persisted.ResolvedBy, "ResolvedBy must never be trusted verbatim from the wire")
	assert.Equal(t, uint(0), persisted.ResolvedBy, "a machine actor's attribution belongs in ResolvedByMachineIdentityID, not ResolvedBy")
	assert.NotEqual(t, uint(0), persisted.ResolvedByMachineIdentityID, "the machine caller's real identity must be recorded")
	require.NotNil(t, persisted.ResolvedAt)
	assert.True(t, persisted.ResolvedAt.Equal(now))
}

// --- ListAccessRequests ---

func TestConformance_ListAccessRequests(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	requester, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-lar-requester", Email: "conformance-lar-requester@example.com",
		DisplayName: "Conformance ListAccessRequests Requester", IsActive: true,
	})
	require.NoError(t, err)
	req1, err := h.ls.CreateAccessRequest(ctx, &models.AccessRequest{ProjectID: h.projectID, UserID: requester.ID, SuggestedRole: "role-1", State: core.AccessRequestPending})
	require.NoError(t, err)
	req2, err := h.ls.CreateAccessRequest(ctx, &models.AccessRequest{ProjectID: h.projectID, UserID: requester.ID, SuggestedRole: "role-2", State: core.AccessRequestRejected})
	require.NoError(t, err)
	_, _ = req1, req2

	localRows, err := h.ls.ListAccessRequests(ctx, h.projectID)
	require.NoError(t, err)
	remoteRows, err := h.rs.ListAccessRequests(ctx, h.projectID)
	require.NoError(t, err, "RemoteStorage.ListAccessRequests must list the SAME requests server-side")
	require.Len(t, remoteRows, len(localRows))
	require.GreaterOrEqual(t, len(localRows), 2)
	localByID := map[uint]*models.AccessRequest{}
	for _, r := range localRows {
		localByID[r.ID] = r
	}
	for _, rr := range remoteRows {
		lr, ok := localByID[rr.ID]
		require.True(t, ok, "remote row %d has no matching local row", rr.ID)
		assertFieldExhaustiveEqual(t, fmt.Sprintf("ListAccessRequests request %d", rr.ID), lr, rr, nil)
	}

	otherProject, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-lar-other-project", "", []string{"dev"})
	require.NoError(t, err)
	emptyLocal, err := h.ls.ListAccessRequests(ctx, otherProject.ID)
	require.NoError(t, err)
	assert.Empty(t, emptyLocal)
	emptyRemote, err := h.rs.ListAccessRequests(ctx, otherProject.ID)
	require.NoError(t, err)
	assert.Empty(t, emptyRemote, "RemoteStorage.ListAccessRequests must return an empty list for a project with no requests")
}

// --- CreateAccessRequestApproval ---

func TestConformance_CreateAccessRequestApproval(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	roleName, err := identity.NewFoldedName("conformance-cara-role")
	require.NoError(t, err)
	role, err := h.ls.CreateRole(ctx, roleName, "conformance test role")
	require.NoError(t, err)

	requester, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-cara-requester", Email: "conformance-cara-requester@example.com",
		DisplayName: "Conformance CreateAccessRequestApproval Requester", IsActive: true,
	})
	require.NoError(t, err)

	newPendingRequest := func() *models.AccessRequest {
		req, err := h.ls.CreateAccessRequest(ctx, &models.AccessRequest{
			ProjectID: h.projectID, UserID: requester.ID, SuggestedRole: role.Name, State: core.AccessRequestPending,
		})
		require.NoError(t, err)
		return req
	}

	// Local sanity baseline: LocalStorage.CreateAccessRequestApproval is a raw
	// INSERT ... ON CONFLICT DO NOTHING -- every field round-trips verbatim.
	localReq := newPendingRequest()
	require.NoError(t, h.ls.CreateAccessRequestApproval(ctx, &models.AccessRequestApproval{RequestID: localReq.ID, ApproverID: h.adminUserID}))
	localRows, err := h.ls.ListAccessRequestApprovals(ctx, localReq.ID)
	require.NoError(t, err)
	require.Len(t, localRows, 1)
	assert.Equal(t, h.adminUserID, localRows[0].ApproverID)

	// Remote: CreateAccessRequestApprovalProxy always derives the approver
	// from the AUTHENTICATED caller, never the wire-supplied approver_id/
	// approver_machine_identity_id (the #1642-shape ceiling fix,
	// access_request_proxy.go's own package doc) -- a machine actor's real
	// identity lands in ApproverMachineIdentityID, never ApproverID, and
	// never the forged values below.
	remoteReq := newPendingRequest()
	const forgedApproverID = 999999
	const forgedApproverMachineID = 888888
	err = h.rs.CreateAccessRequestApproval(ctx, &models.AccessRequestApproval{
		RequestID: remoteReq.ID, ApproverID: forgedApproverID, ApproverMachineIdentityID: forgedApproverMachineID,
	})
	require.NoError(t, err, "RemoteStorage.CreateAccessRequestApproval must succeed for a genuine, non-self, zero-permission-role approver")
	remoteRows, err := h.ls.ListAccessRequestApprovals(ctx, remoteReq.ID)
	require.NoError(t, err)
	require.Len(t, remoteRows, 1)
	assert.NotEqual(t, uint(forgedApproverID), remoteRows[0].ApproverID)
	assert.Equal(t, uint(0), remoteRows[0].ApproverID, "a machine approver's ApproverID (the USER discriminator) must stay 0")
	assert.NotEqual(t, uint(forgedApproverMachineID), remoteRows[0].ApproverMachineIdentityID)
	assert.NotEqual(t, uint(0), remoteRows[0].ApproverMachineIdentityID, "the machine approver's real identity must be recorded")

	// Negative: a duplicate sign-off from the SAME approver (the harness's own
	// machine/node credential, twice) must be a benign no-op (ON CONFLICT DO
	// NOTHING, local_invitations.go), not a second row and not an error --
	// the M-of-K dual-control count's own race backstop, unchanged by this
	// HTTP hop.
	err = h.rs.CreateAccessRequestApproval(ctx, &models.AccessRequestApproval{RequestID: remoteReq.ID})
	require.NoError(t, err, "a duplicate approval from the same approver must not error")
	afterDuplicate, err := h.ls.ListAccessRequestApprovals(ctx, remoteReq.ID)
	require.NoError(t, err)
	assert.Len(t, afterDuplicate, 1, "a duplicate approval from the same approver must not create a second row")
}

// --- ListAccessRequestApprovals ---

func TestConformance_ListAccessRequestApprovals(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	requester, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-lara-requester", Email: "conformance-lara-requester@example.com",
		DisplayName: "Conformance ListAccessRequestApprovals Requester", IsActive: true,
	})
	require.NoError(t, err)
	req, err := h.ls.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: h.projectID, UserID: requester.ID, SuggestedRole: "irrelevant", State: core.AccessRequestPending,
	})
	require.NoError(t, err)

	approver1, err := h.ls.CreateUser(ctx, &models.User{
		Username: "conformance-lara-approver1", Email: "conformance-lara-approver1@example.com",
		DisplayName: "Conformance Approver 1", IsActive: true,
	})
	require.NoError(t, err)
	require.NoError(t, h.ls.CreateAccessRequestApproval(ctx, &models.AccessRequestApproval{RequestID: req.ID, ApproverID: approver1.ID}))
	require.NoError(t, h.ls.CreateAccessRequestApproval(ctx, &models.AccessRequestApproval{RequestID: req.ID, ApproverMachineIdentityID: 777}))

	localRows, err := h.ls.ListAccessRequestApprovals(ctx, req.ID)
	require.NoError(t, err)
	remoteRows, err := h.rs.ListAccessRequestApprovals(ctx, req.ID)
	require.NoError(t, err, "RemoteStorage.ListAccessRequestApprovals must list the SAME approvals server-side")
	require.Len(t, remoteRows, len(localRows))
	require.Len(t, localRows, 2)
	for i := range localRows {
		assertFieldExhaustiveEqual(t, fmt.Sprintf("ListAccessRequestApprovals approval index %d", i), localRows[i], remoteRows[i], nil)
	}

	// Negative: a request with no approvals yet must return an empty list.
	freshReq, err := h.ls.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: h.projectID, UserID: requester.ID, SuggestedRole: "irrelevant", State: core.AccessRequestPending,
	})
	require.NoError(t, err)
	emptyLocal, err := h.ls.ListAccessRequestApprovals(ctx, freshReq.ID)
	require.NoError(t, err)
	assert.Empty(t, emptyLocal)
	emptyRemote, err := h.rs.ListAccessRequestApprovals(ctx, freshReq.ID)
	require.NoError(t, err)
	assert.Empty(t, emptyRemote, "RemoteStorage.ListAccessRequestApprovals must return an empty list for a request with no approvals")
}

// --- CreateAccessReviewCampaign ---

func TestConformance_CreateAccessReviewCampaign(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	// Local sanity baseline: LocalStorage.CreateAccessReviewCampaign is a raw
	// create with no forcing -- every field we send round-trips verbatim.
	localInput := &models.AccessReviewCampaign{
		ProjectID: h.projectID, Name: "conformance-carc-local", State: core.CampaignStateOpen,
		CreatedBy: h.adminUserID, Degraded: true, DegradedReasons: []string{"conformance-reason-local"},
	}
	localCreated, err := h.ls.CreateAccessReviewCampaign(ctx, localInput)
	require.NoError(t, err)
	localPersisted, err := h.ls.GetAccessReviewCampaign(ctx, localCreated.ID)
	require.NoError(t, err)
	assertFieldExhaustiveEqual(t, "LocalStorage.CreateAccessReviewCampaign (sanity baseline)", localInput, localPersisted,
		map[string]bool{"ID": true, "CreatedAt": true})

	// Remote: CreateAccessReviewCampaignProxy (ARC-003) unconditionally
	// normalizes every lifecycle field to a freshly-opened campaign's values
	// regardless of what the caller sends, and forces CreatedBy to the
	// AUTHENTICATED caller -- never the wire. The harness's machine/node
	// credential's actorID(r) is always 0, so CreatedBy lands as 0, not the
	// forged value below.
	const forgedCreatedBy = 999999
	forgedClosedAt := time.Now().UTC()
	remoteInput := &models.AccessReviewCampaign{
		ProjectID: h.projectID, Name: "conformance-carc-remote", State: "closed", /* forged: must normalize to open */
		CreatedBy: forgedCreatedBy, ClosedBy: 424242, ClosedAt: &forgedClosedAt, ForcedIncomplete: true, /* forged */
		Degraded: true, DegradedReasons: []string{"conformance-reason-remote"},
	}
	remoteCreated, err := h.rs.CreateAccessReviewCampaign(ctx, remoteInput)
	require.NoError(t, err, "RemoteStorage.CreateAccessReviewCampaign must succeed for a valid project_id+name")
	remotePersisted, err := h.ls.GetAccessReviewCampaign(ctx, remoteCreated.ID)
	require.NoError(t, err)

	assert.Equal(t, core.CampaignStateOpen, remotePersisted.State, "a caller-supplied lifecycle state must be normalized to open (ARC-003)")
	assert.Equal(t, uint(0), remotePersisted.ClosedBy, "a caller-supplied closed_by must be stripped on create (ARC-003)")
	assert.Nil(t, remotePersisted.ClosedAt, "a caller-supplied closed_at must be stripped on create (ARC-003)")
	assert.False(t, remotePersisted.ForcedIncomplete, "a caller-supplied forced_incomplete must be stripped on create (ARC-003)")
	assert.NotEqual(t, uint(forgedCreatedBy), remotePersisted.CreatedBy,
		"CreatedBy must be derived from the authenticated caller, never trusted from the wire")
	assert.Equal(t, uint(0), remotePersisted.CreatedBy,
		"the harness's machine/node credential's actorID(r) is always 0 (no UserID) -- CreatedBy lands as 0")

	// KNOWN WIRE-FIDELITY GAP -- see this file's package doc, item 2. Asserting
	// the CURRENT (unfortunate) behavior rather than excluding the field
	// silently.
	assert.Equal(t, uint(0), remotePersisted.CreatedByMachineIdentityID,
		"KNOWN GAP: the machine caller's real identity is silently lost -- CreatedByMachineIdentityID is not "+
			"carried on this wire at all today (see this file's package doc)")

	assertFieldExhaustiveEqual(t, "RemoteStorage.CreateAccessReviewCampaign (wire round trip, ARC-003 fields excluded -- see comments)",
		remoteInput, remotePersisted,
		map[string]bool{
			"ID": true, "CreatedAt": true, "State": true, "CreatedBy": true, "ClosedBy": true, "ClosedAt": true,
			"ForcedIncomplete": true, "CreatedByMachineIdentityID": true, "ClosedByMachineIdentityID": true,
		})
}

// --- GetAccessReviewCampaign ---

func TestConformance_GetAccessReviewCampaign(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	c, err := h.ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: h.projectID, Name: "conformance-garc-campaign", State: core.CampaignStateOpen,
		CreatedBy: h.adminUserID, Degraded: true, DegradedReasons: []string{"conformance-reason"},
	})
	require.NoError(t, err)

	localFound, err := h.ls.GetAccessReviewCampaign(ctx, c.ID)
	require.NoError(t, err)
	remoteFound, err := h.rs.GetAccessReviewCampaign(ctx, c.ID)
	require.NoError(t, err, "RemoteStorage.GetAccessReviewCampaign must find a campaign that genuinely exists")
	assertFieldExhaustiveEqual(t, "GetAccessReviewCampaign", localFound, remoteFound, nil)

	_, localErr := h.ls.GetAccessReviewCampaign(ctx, c.ID+999999)
	_, remoteErr := h.rs.GetAccessReviewCampaign(ctx, c.ID+999999)
	assert.Error(t, localErr, "sanity: a nonexistent campaign ID must error locally")
	assert.Error(t, remoteErr, "RemoteStorage.GetAccessReviewCampaign must error for a nonexistent campaign ID")
}

// --- ListAccessReviewCampaigns ---

func TestConformance_ListAccessReviewCampaigns(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	c1, err := h.ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: h.projectID, Name: "conformance-larc-1", State: core.CampaignStateOpen, CreatedBy: h.adminUserID,
	})
	require.NoError(t, err)
	c2, err := h.ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: h.projectID, Name: "conformance-larc-2", State: core.CampaignStateClosed, CreatedBy: h.adminUserID,
	})
	require.NoError(t, err)
	_, _ = c1, c2

	localRows, err := h.ls.ListAccessReviewCampaigns(ctx, h.projectID)
	require.NoError(t, err)
	remoteRows, err := h.rs.ListAccessReviewCampaigns(ctx, h.projectID)
	require.NoError(t, err, "RemoteStorage.ListAccessReviewCampaigns must list the SAME campaigns server-side")
	require.Len(t, remoteRows, len(localRows))
	require.GreaterOrEqual(t, len(localRows), 2)
	localByID := map[uint]*models.AccessReviewCampaign{}
	for _, c := range localRows {
		localByID[c.ID] = c
	}
	for _, rc := range remoteRows {
		lc, ok := localByID[rc.ID]
		require.True(t, ok, "remote row %d has no matching local row", rc.ID)
		assertFieldExhaustiveEqual(t, fmt.Sprintf("ListAccessReviewCampaigns campaign %d", rc.ID), lc, rc, nil)
	}

	// Negative: a fresh project with zero campaigns must return an empty list.
	otherProject, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-larc-other-project", "", []string{"dev"})
	require.NoError(t, err)
	emptyLocal, err := h.ls.ListAccessReviewCampaigns(ctx, otherProject.ID)
	require.NoError(t, err)
	assert.Empty(t, emptyLocal)
	emptyRemote, err := h.rs.ListAccessReviewCampaigns(ctx, otherProject.ID)
	require.NoError(t, err)
	assert.Empty(t, emptyRemote, "RemoteStorage.ListAccessReviewCampaigns must return an empty list for a project with no campaigns")
}

// --- GetOpenAccessReviewCampaign ---

func TestConformance_GetOpenAccessReviewCampaign(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	campaign, err := h.ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: h.projectID, Name: "conformance-goarc-campaign", State: core.CampaignStateOpen, CreatedBy: h.adminUserID,
	})
	require.NoError(t, err)

	localFound, err := h.ls.GetOpenAccessReviewCampaign(ctx, h.projectID)
	require.NoError(t, err)
	require.NotNil(t, localFound, "sanity: LocalStorage must find the open campaign")
	remoteFound, err := h.rs.GetOpenAccessReviewCampaign(ctx, h.projectID)
	require.NoError(t, err)
	require.NotNil(t, remoteFound, "RemoteStorage.GetOpenAccessReviewCampaign must find the SAME open campaign server-side")
	assertFieldExhaustiveEqual(t, "GetOpenAccessReviewCampaign (found)", localFound, remoteFound, nil)
	assert.Equal(t, campaign.ID, remoteFound.ID)

	// Negative: a project with no open campaign at all must return (nil, nil)
	// -- not an error, not a 404 -- on both paths (a fresh project with zero
	// campaign history).
	otherProject, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-goarc-other-project", "", []string{"dev"})
	require.NoError(t, err)
	localNone, err := h.ls.GetOpenAccessReviewCampaign(ctx, otherProject.ID)
	require.NoError(t, err)
	assert.Nil(t, localNone, "sanity: no campaign at all means no open campaign")
	remoteNone, err := h.rs.GetOpenAccessReviewCampaign(ctx, otherProject.ID)
	require.NoError(t, err)
	assert.Nil(t, remoteNone, "RemoteStorage.GetOpenAccessReviewCampaign must also report no open campaign as (nil, nil), not an error")
}

// --- GetLatestClosedAccessReviewCampaign ---

func TestConformance_GetLatestClosedAccessReviewCampaign(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	older, err := h.ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: h.projectID, Name: "conformance-glcarc-older", State: core.CampaignStateClosed,
		CreatedBy: h.adminUserID, CreatedAt: time.Now().Add(-2 * time.Hour).UTC(),
	})
	require.NoError(t, err)
	newer, err := h.ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: h.projectID, Name: "conformance-glcarc-newer", State: core.CampaignStateClosed,
		CreatedBy: h.adminUserID, CreatedAt: time.Now().Add(-1 * time.Hour).UTC(),
	})
	require.NoError(t, err)
	_ = older

	localFound, err := h.ls.GetLatestClosedAccessReviewCampaign(ctx, h.projectID)
	require.NoError(t, err)
	require.NotNil(t, localFound)
	assert.Equal(t, newer.ID, localFound.ID, "sanity: LocalStorage must pick the most recently created closed campaign")

	remoteFound, err := h.rs.GetLatestClosedAccessReviewCampaign(ctx, h.projectID)
	require.NoError(t, err)
	require.NotNil(t, remoteFound, "RemoteStorage.GetLatestClosedAccessReviewCampaign must find the SAME latest-closed campaign server-side")
	assert.Equal(t, newer.ID, remoteFound.ID,
		"RemoteStorage.GetLatestClosedAccessReviewCampaign must pick the most recently created closed campaign, not an arbitrary or oldest one")
	assertFieldExhaustiveEqual(t, "GetLatestClosedAccessReviewCampaign (found)", localFound, remoteFound, nil)

	// Negative: a project that has never had a campaign must return (nil, nil).
	otherProject, err := h.upstreamCore.CreateProjectWithEnvs(ctx, "conformance-glcarc-other-project", "", []string{"dev"})
	require.NoError(t, err)
	localNone, err := h.ls.GetLatestClosedAccessReviewCampaign(ctx, otherProject.ID)
	require.NoError(t, err)
	assert.Nil(t, localNone)
	remoteNone, err := h.rs.GetLatestClosedAccessReviewCampaign(ctx, otherProject.ID)
	require.NoError(t, err)
	assert.Nil(t, remoteNone, "RemoteStorage.GetLatestClosedAccessReviewCampaign must report (nil, nil) for a project with no campaign history")
}

// --- CreateAccessReviewItems ---

func TestConformance_CreateAccessReviewItems(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newOpenCampaign := func(suffix string) *models.AccessReviewCampaign {
		c, err := h.ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
			ProjectID: h.projectID, Name: "conformance-cari-campaign-" + suffix, State: core.CampaignStateOpen, CreatedBy: h.adminUserID,
		})
		require.NoError(t, err)
		return c
	}

	// Local sanity baseline: LocalStorage.CreateAccessReviewItems is a raw
	// bulk create -- every field, including Decision/DecidedBy/DecidedAt,
	// round-trips verbatim (no ARC-004 normalization at the storage layer).
	localCampaign := newOpenCampaign("local")
	localItem := &models.AccessReviewItem{
		CampaignID: localCampaign.ID, PrincipalType: "role", PrincipalID: 42, PrincipalName: "conformance-principal-local",
		Source: "role", RoleID: 7, RoleName: "conformance-role-local", AccessLevel: "read",
		EnvironmentID: h.environmentID, SecretID: 99, SecretName: "conformance-secret-local",
		Decision: core.ReviewItemAttested, DecidedBy: h.adminUserID,
	}
	require.NoError(t, h.ls.CreateAccessReviewItems(ctx, []*models.AccessReviewItem{localItem}))
	localPersistedRows, err := h.ls.ListAccessReviewItems(ctx, localCampaign.ID)
	require.NoError(t, err)
	require.Len(t, localPersistedRows, 1)
	assertFieldExhaustiveEqual(t, "LocalStorage.CreateAccessReviewItems (sanity baseline)", localItem, localPersistedRows[0],
		map[string]bool{"ID": true})

	// Remote: CreateAccessReviewItemsProxy (ARC-004) unconditionally strips
	// any pre-supplied decision state -- every newly created item must start
	// pending with no decider, regardless of what the caller sends.
	remoteCampaign := newOpenCampaign("remote")
	forgedDecidedAt := time.Now().UTC()
	remoteItem := &models.AccessReviewItem{
		CampaignID: remoteCampaign.ID, PrincipalType: "role", PrincipalID: 42, PrincipalName: "conformance-principal-remote",
		Source: "role", RoleID: 7, RoleName: "conformance-role-remote", AccessLevel: "read",
		EnvironmentID: h.environmentID, SecretID: 99, SecretName: "conformance-secret-remote",
		Decision: core.ReviewItemAttested, DecidedBy: 999999, DecidedAt: &forgedDecidedAt, // forged: must be stripped
	}
	require.NoError(t, h.rs.CreateAccessReviewItems(ctx, []*models.AccessReviewItem{remoteItem}),
		"RemoteStorage.CreateAccessReviewItems must succeed for a valid campaign")
	remotePersistedRows, err := h.ls.ListAccessReviewItems(ctx, remoteCampaign.ID)
	require.NoError(t, err)
	require.Len(t, remotePersistedRows, 1)
	assert.Equal(t, core.ReviewItemPending, remotePersistedRows[0].Decision, "a caller-supplied decision must be stripped to pending (ARC-004)")
	assert.Equal(t, uint(0), remotePersistedRows[0].DecidedBy, "a caller-supplied decided_by must be stripped on create (ARC-004)")
	assert.Nil(t, remotePersistedRows[0].DecidedAt, "a caller-supplied decided_at must be stripped on create (ARC-004)")
	assertFieldExhaustiveEqual(t, "RemoteStorage.CreateAccessReviewItems (wire round trip, ARC-004 fields excluded)",
		remoteItem, remotePersistedRows[0],
		map[string]bool{"ID": true, "Decision": true, "DecidedBy": true, "DecidedAt": true})

	// Negative: an empty item slice is a documented no-op on both paths --
	// RemoteStorage.CreateAccessReviewItems returns early client-side (it
	// derives the campaign ID from items[0] and would otherwise panic on an
	// empty slice), making no HTTP call at all.
	assert.NoError(t, h.ls.CreateAccessReviewItems(ctx, nil))
	assert.NoError(t, h.rs.CreateAccessReviewItems(ctx, nil))
}

// --- ListAccessReviewItems ---

func TestConformance_ListAccessReviewItems(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	campaign, err := h.ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: h.projectID, Name: "conformance-lari-campaign", State: core.CampaignStateOpen, CreatedBy: h.adminUserID,
	})
	require.NoError(t, err)
	item1 := &models.AccessReviewItem{CampaignID: campaign.ID, PrincipalType: "role", PrincipalID: 1, Source: "role", AccessLevel: "read", EnvironmentID: h.environmentID, Decision: core.ReviewItemPending}
	item2 := &models.AccessReviewItem{CampaignID: campaign.ID, PrincipalType: "user", PrincipalID: 2, Source: "owner", AccessLevel: "write", EnvironmentID: h.environmentID, Decision: core.ReviewItemPending}
	require.NoError(t, h.ls.CreateAccessReviewItems(ctx, []*models.AccessReviewItem{item1, item2}))

	localRows, err := h.ls.ListAccessReviewItems(ctx, campaign.ID)
	require.NoError(t, err)
	remoteRows, err := h.rs.ListAccessReviewItems(ctx, campaign.ID)
	require.NoError(t, err, "RemoteStorage.ListAccessReviewItems must list the SAME items server-side")
	require.Len(t, remoteRows, len(localRows))
	require.Len(t, localRows, 2)
	for i := range localRows {
		assertFieldExhaustiveEqual(t, fmt.Sprintf("ListAccessReviewItems item index %d", i), localRows[i], remoteRows[i], nil)
	}

	otherCampaign, err := h.ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: h.projectID, Name: "conformance-lari-empty-campaign", State: core.CampaignStateOpen, CreatedBy: h.adminUserID,
	})
	require.NoError(t, err)
	emptyLocal, err := h.ls.ListAccessReviewItems(ctx, otherCampaign.ID)
	require.NoError(t, err)
	assert.Empty(t, emptyLocal)
	emptyRemote, err := h.rs.ListAccessReviewItems(ctx, otherCampaign.ID)
	require.NoError(t, err)
	assert.Empty(t, emptyRemote, "RemoteStorage.ListAccessReviewItems must return an empty list for a campaign with no items")
}

// --- CountPendingAccessReviewItems ---

func TestConformance_CountPendingAccessReviewItems(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	newCampaignWithItems := func(suffix string, pending, decided int) *models.AccessReviewCampaign {
		c, err := h.ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
			ProjectID: h.projectID, Name: "conformance-cpari-campaign-" + suffix, State: core.CampaignStateOpen, CreatedBy: h.adminUserID,
		})
		require.NoError(t, err)
		var items []*models.AccessReviewItem
		for i := 0; i < pending; i++ {
			items = append(items, &models.AccessReviewItem{
				CampaignID: c.ID, PrincipalType: "role", PrincipalID: uint(i + 1), Source: "role",
				AccessLevel: "read", EnvironmentID: h.environmentID, Decision: core.ReviewItemPending,
			})
		}
		for i := 0; i < decided; i++ {
			items = append(items, &models.AccessReviewItem{
				CampaignID: c.ID, PrincipalType: "role", PrincipalID: uint(100 + i), Source: "role",
				AccessLevel: "read", EnvironmentID: h.environmentID, Decision: core.ReviewItemAttested, DecidedBy: h.adminUserID,
			})
		}
		require.NoError(t, h.ls.CreateAccessReviewItems(ctx, items))
		return c
	}

	localCampaign := newCampaignWithItems("local", 2, 1)
	localCount, err := h.ls.CountPendingAccessReviewItems(ctx, localCampaign.ID)
	require.NoError(t, err)
	assert.Equal(t, 2, localCount, "sanity: LocalStorage must count only the pending items")

	remoteCampaign := newCampaignWithItems("remote", 2, 1)
	remoteCount, err := h.rs.CountPendingAccessReviewItems(ctx, remoteCampaign.ID)
	require.NoError(t, err, "RemoteStorage.CountPendingAccessReviewItems must succeed")
	assert.Equal(t, 2, remoteCount, "RemoteStorage.CountPendingAccessReviewItems must count only the pending items, not every item")

	// Negative: a campaign with zero pending items (every item already decided) must count 0.
	allDecided := newCampaignWithItems("all-decided", 0, 3)
	zeroCount, err := h.rs.CountPendingAccessReviewItems(ctx, allDecided.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, zeroCount, "RemoteStorage.CountPendingAccessReviewItems must report 0 when every item is already decided")
}

// --- GetAccessReviewItem ---

func TestConformance_GetAccessReviewItem(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	campaign, err := h.ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: h.projectID, Name: "conformance-gari-campaign", State: core.CampaignStateOpen, CreatedBy: h.adminUserID,
	})
	require.NoError(t, err)
	item := &models.AccessReviewItem{
		CampaignID: campaign.ID, PrincipalType: "role", PrincipalID: 5, PrincipalName: "conformance-principal",
		Source: "role", RoleID: 3, RoleName: "conformance-role", AccessLevel: "read", EnvironmentID: h.environmentID,
		SecretID: 9, SecretName: "conformance-secret", Decision: core.ReviewItemPending,
	}
	require.NoError(t, h.ls.CreateAccessReviewItems(ctx, []*models.AccessReviewItem{item}))

	localFound, err := h.ls.GetAccessReviewItem(ctx, item.ID)
	require.NoError(t, err)
	remoteFound, err := h.rs.GetAccessReviewItem(ctx, item.ID)
	require.NoError(t, err, "RemoteStorage.GetAccessReviewItem must find an item that genuinely exists")
	assertFieldExhaustiveEqual(t, "GetAccessReviewItem", localFound, remoteFound, nil)

	_, localErr := h.ls.GetAccessReviewItem(ctx, item.ID+999999)
	_, remoteErr := h.rs.GetAccessReviewItem(ctx, item.ID+999999)
	assert.Error(t, localErr, "sanity: a nonexistent item ID must error locally")
	assert.Error(t, remoteErr, "RemoteStorage.GetAccessReviewItem must error for a nonexistent item ID")
}

// --- UpdateAccessReviewItem ---

func TestConformance_UpdateAccessReviewItem(t *testing.T) {
	h := newConformanceHarness(t)
	ctx := context.Background()

	// UpdateAccessReviewItemProxy hard-refuses any caller that is not an
	// attributable, authenticated HUMAN (ARC-005: "an independent reviewer
	// concept has no meaning for a machine caller") -- h.rs cannot drive this
	// route at all. Mint a second RemoteStorage client authenticated with a
	// real user session against the SAME server, mirroring tranche 3's
	// RevokeBreakGlassActivation.
	userToken := createTestToken(t, h.upstreamCore)
	rsAsUser, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: h.server.URL, APIKey: userToken, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)

	newOpenCampaign := func(suffix string) *models.AccessReviewCampaign {
		c, err := h.ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
			ProjectID: h.projectID, Name: "conformance-uari-campaign-" + suffix, State: core.CampaignStateOpen, CreatedBy: h.adminUserID,
		})
		require.NoError(t, err)
		return c
	}
	newPendingItem := func(campaignID, principalID uint) *models.AccessReviewItem {
		item := &models.AccessReviewItem{
			CampaignID: campaignID, PrincipalType: "role", PrincipalID: principalID, PrincipalName: "conformance-principal",
			Source: "role", AccessLevel: "read", EnvironmentID: h.environmentID, Decision: core.ReviewItemPending,
		}
		require.NoError(t, h.ls.CreateAccessReviewItems(ctx, []*models.AccessReviewItem{item}))
		return item
	}

	// A machine/node caller must be refused outright, regardless of the item's state.
	machineRefusedCampaign := newOpenCampaign("machine-refused")
	machineRefusedItem := newPendingItem(machineRefusedCampaign.ID, 1)
	_, err = h.rs.UpdateAccessReviewItem(ctx, &models.AccessReviewItem{ID: machineRefusedItem.ID, Decision: core.ReviewItemAttested})
	assert.Error(t, err, "RemoteStorage.UpdateAccessReviewItem must refuse a machine/node caller outright -- an "+
		"independent reviewer must be an attributable, authenticated human")

	// Self-certification precondition: a reviewer may not decide their OWN
	// access-review item -- checked against the item's REAL, server-fetched
	// principal (the 2026-09-04 finding fixed in this exact handler; see its
	// package doc), not a client-asserted PrincipalType/PrincipalID.
	admin, err := h.upstreamCore.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	selfCertCampaign := newOpenCampaign("self-cert")
	selfCertItem := &models.AccessReviewItem{
		CampaignID: selfCertCampaign.ID, PrincipalType: "user", PrincipalID: admin.ID, PrincipalName: "testadmin",
		Source: "role", AccessLevel: "read", EnvironmentID: h.environmentID, Decision: core.ReviewItemPending,
	}
	require.NoError(t, h.ls.CreateAccessReviewItems(ctx, []*models.AccessReviewItem{selfCertItem}))
	_, err = rsAsUser.UpdateAccessReviewItem(ctx, &models.AccessReviewItem{
		ID: selfCertItem.ID, Decision: core.ReviewItemAttested,
		PrincipalType: "role", PrincipalID: 999999, // lying about the principal must not bypass the check
	})
	assert.Error(t, err, "a reviewer must not be able to self-certify their own item by lying about "+
		"PrincipalType/PrincipalID on the wire -- the check is anchored to the server-fetched real principal")
	stillPending, err := h.ls.GetAccessReviewItem(ctx, selfCertItem.ID)
	require.NoError(t, err)
	assert.Equal(t, core.ReviewItemPending, stillPending.Decision, "a rejected self-certification attempt must not have altered the item")

	// Wrong-precondition: a campaign that is CLOSED must refuse a decision
	// (Matched=false) even though the item itself is still pending -- #343's
	// atomic (item-pending AND campaign-open) conditional UPDATE.
	closedCampaign, err := h.ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: h.projectID, Name: "conformance-uari-closed-campaign", State: core.CampaignStateClosed, CreatedBy: h.adminUserID,
	})
	require.NoError(t, err)
	closedItem := newPendingItem(closedCampaign.ID, 2)
	closedMatched, err := rsAsUser.UpdateAccessReviewItem(ctx, &models.AccessReviewItem{ID: closedItem.ID, Decision: core.ReviewItemAttested})
	require.NoError(t, err)
	assert.False(t, closedMatched, "RemoteStorage.UpdateAccessReviewItem must report no match for an item whose campaign is closed, not silently decide it")
	stillPendingClosed, err := h.ls.GetAccessReviewItem(ctx, closedItem.ID)
	require.NoError(t, err)
	assert.Equal(t, core.ReviewItemPending, stillPendingClosed.Decision, "a decision against a closed campaign must not have altered the item")

	// Same wrong-precondition, local sanity baseline: LocalStorage.UpdateAccessReviewItem
	// applies the identical atomic conditional.
	localClosedCampaign, err := h.ls.CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: h.projectID, Name: "conformance-uari-local-closed-campaign", State: core.CampaignStateClosed, CreatedBy: h.adminUserID,
	})
	require.NoError(t, err)
	localClosedItem := newPendingItem(localClosedCampaign.ID, 3)
	localClosedItem.Decision = core.ReviewItemAttested
	localMatched, err := h.ls.UpdateAccessReviewItem(ctx, localClosedItem)
	require.NoError(t, err)
	assert.False(t, localMatched, "sanity: LocalStorage must also refuse a decision against a closed campaign")

	// Correct path: an open campaign, a pending item, a non-self reviewer --
	// forged decided_by on the wire must be discarded, replaced with the
	// AUTHENTICATED reviewer's real user ID (ARC-005), and a forged
	// PrincipalType/PrincipalID/CampaignID must not overwrite the item's
	// frozen evidence snapshot (the handler re-fetches and applies only
	// Decision/Reason/DecidedBy/DecidedAt onto the real row).
	openCampaign := newOpenCampaign("correct")
	correctItem := newPendingItem(openCampaign.ID, 4)
	const forgedDecidedBy = 999999
	decidedAt := time.Now().UTC()
	matched, err := rsAsUser.UpdateAccessReviewItem(ctx, &models.AccessReviewItem{
		ID: correctItem.ID, Decision: core.ReviewItemRevoked, Reason: "conformance revoke reason",
		DecidedBy: forgedDecidedBy, DecidedAt: &decidedAt,
		PrincipalType: "forged-type", PrincipalID: 424242, CampaignID: 424242,
	})
	require.NoError(t, err, "RemoteStorage.UpdateAccessReviewItem must match a genuinely pending item in a genuinely open campaign")
	assert.True(t, matched)
	persisted, err := h.ls.GetAccessReviewItem(ctx, correctItem.ID)
	require.NoError(t, err)
	assert.Equal(t, core.ReviewItemRevoked, persisted.Decision)
	assert.Equal(t, "conformance revoke reason", persisted.Reason)
	assert.NotEqual(t, uint(forgedDecidedBy), persisted.DecidedBy, "DecidedBy must never be trusted verbatim from the wire")
	assert.Equal(t, admin.ID, persisted.DecidedBy, "DecidedBy must be the AUTHENTICATED reviewer's real user ID")
	require.NotNil(t, persisted.DecidedAt)
	assert.True(t, persisted.DecidedAt.Equal(decidedAt))
	assert.Equal(t, correctItem.PrincipalType, persisted.PrincipalType, "the item's frozen PrincipalType must survive unchanged")
	assert.Equal(t, correctItem.PrincipalID, persisted.PrincipalID, "the item's frozen PrincipalID must survive unchanged")
	assert.Equal(t, correctItem.CampaignID, persisted.CampaignID, "the item's CampaignID must survive unchanged")
}

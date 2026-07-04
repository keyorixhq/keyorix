package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GetCompliancePosture rolls up second-factor coverage, access-review campaign
// coverage, dormant role grants, and break-glass usage across the deployment.
func TestGetCompliancePosture_RollsUpControls(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.AuditEvent{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.BreakGlassActivation{}, &models.RotationPolicy{},
	))

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.CreateTestUser(t, "bob", 11)
	// alice has a second factor; bob does not → 50% coverage.
	require.NoError(t, h.DB.Model(&models.User{}).Where("id = ?", 10).Update("mfa_enabled", true).Error)

	// alice holds a role grant in project 2 with no secret activity → dormant.
	h.AssignUserRole(t, 10, 3, uptr(proj))
	// An open campaign on project 2.
	_, err := h.CoreService.OpenAccessReviewCampaign(ctx, 1, proj, "Q4")
	require.NoError(t, err)
	// An active break-glass activation in project 2.
	future := time.Now().Add(time.Hour)
	require.NoError(t, h.DB.Create(&models.BreakGlassActivation{
		ProjectID: proj, UserID: 10, RoleID: 3, RoleName: "editor",
		Justification: "incident", State: "active", ExpiresAt: &future, CreatedAt: time.Now(),
	}).Error)

	p, err := h.CoreService.GetCompliancePosture(ctx)
	require.NoError(t, err)

	// Identity: 2 active users, 1 with a second factor.
	assert.Equal(t, 2, p.Identity.ActiveUsers)
	assert.Equal(t, 1, p.Identity.UsersWithSecondFactor)
	assert.Equal(t, 50, p.Identity.SecondFactorPercent)

	// Access governance: one open campaign covering one project; alice is dormant.
	assert.Equal(t, 1, p.AccessGovernance.OpenCampaigns)
	assert.Equal(t, 1, p.AccessGovernance.ProjectsWithOpenCampaign)
	assert.GreaterOrEqual(t, p.AccessGovernance.DormantRoleGrants, 1)
	assert.GreaterOrEqual(t, p.AccessGovernance.PendingItems, 1)

	// Emergency access: the active break-glass activation is counted.
	assert.Equal(t, 1, p.EmergencyAccess.ActiveActivations)
	assert.Equal(t, 1, p.EmergencyAccess.TotalActivations)

	// Audit integrity: the chain of legitimately-written events verifies.
	assert.True(t, p.AuditIntegrity.ChainVerified)
}

// GetCompliancePosture rolls up the dual-control access-request/approval workflow
// (#257): total requests plus per-state counts across every project, and the
// currently-configured dual-control approval threshold. A stale pending request
// past its ExpiresAt must roll up as expired, not pending, even though the seeded
// row's persisted State column still literally says "pending" (mirroring how
// applyAccessRequestEffectiveExpiry — used by the posture/evidence read path —
// corrects this without a write).
func TestGetCompliancePosture_AccessRequests(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.AuditEvent{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.BreakGlassActivation{}, &models.RotationPolicy{},
		&models.AccessRequest{}, &models.AccessRequestApproval{},
	))

	ctx := context.Background()
	h.CreateTestUser(t, "requester1", 20)
	h.CreateTestUser(t, "requester2", 21)
	h.CreateTestUser(t, "requester3", 22)
	h.CreateTestUser(t, "requester4", 23)
	h.CreateTestUser(t, "requester5", 24)

	now := time.Now()
	future := now.Add(time.Hour)
	past := now.Add(-time.Hour)

	// Project 1: one still-pending request, one PAST-expiry request that is still
	// persisted with State="pending" (the lazy-expiry transition hasn't landed yet),
	// and one withdrawn request.
	require.NoError(t, h.DB.Create(&models.AccessRequest{
		ProjectID: 1, UserID: 20, SuggestedRole: "viewer", State: "pending",
		ExpiresAt: &future, CreatedAt: now,
	}).Error)
	require.NoError(t, h.DB.Create(&models.AccessRequest{
		ProjectID: 1, UserID: 21, SuggestedRole: "viewer", State: "pending",
		ExpiresAt: &past, CreatedAt: now,
	}).Error)
	require.NoError(t, h.DB.Create(&models.AccessRequest{
		ProjectID: 1, UserID: 24, SuggestedRole: "viewer", State: "withdrawn",
		CreatedAt: now, ResolvedAt: &now,
	}).Error)

	// Project 2: one approved request, one rejected request.
	require.NoError(t, h.DB.Create(&models.AccessRequest{
		ProjectID: 2, UserID: 22, SuggestedRole: "editor", GrantedRole: "editor", State: "approved",
		CreatedAt: now, ResolvedAt: &now,
	}).Error)
	require.NoError(t, h.DB.Create(&models.AccessRequest{
		ProjectID: 2, UserID: 23, SuggestedRole: "editor", State: "rejected",
		CreatedAt: now, ResolvedAt: &now,
	}).Error)

	p, err := h.CoreService.GetCompliancePosture(ctx)
	require.NoError(t, err)

	assert.Equal(t, 5, p.AccessRequests.TotalRequests)
	assert.Equal(t, 1, p.AccessRequests.Pending)
	assert.Equal(t, 1, p.AccessRequests.Expired) // past-ExpiresAt row rolls up as expired, not pending
	assert.Equal(t, 1, p.AccessRequests.Approved)
	assert.Equal(t, 1, p.AccessRequests.Rejected)
	assert.Equal(t, 1, p.AccessRequests.Withdrawn)
	// No SetDualControlPolicy call — the default single-approver threshold applies.
	assert.Equal(t, 1, p.AccessRequests.RequiredApprovals)

	// The evidence pack carries the same underlying rows the posture counted.
	ev, err := h.CoreService.GenerateComplianceEvidence(ctx)
	require.NoError(t, err)
	assert.Len(t, ev.AccessRequests, 5)
	assert.Equal(t, p.AccessRequests, ev.Posture.AccessRequests)

	// Raising the dual-control threshold surfaces in the posture immediately.
	h.CoreService.SetDualControlPolicy(2)
	p2, err := h.CoreService.GetCompliancePosture(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, p2.AccessRequests.RequiredApprovals)
}

// A recent secret access keeps a role grant out of the dormant tally.
func TestCompliancePosture_RecentActivityNotDormant(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.AuditEvent{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.BreakGlassActivation{}, &models.RotationPolicy{},
	))

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj))

	aid := uint(10)
	pid := proj
	require.NoError(t, h.DB.Create(&models.AuditEvent{
		EventType: "secret.read", UserID: &aid, ProjectID: &pid, EventTime: time.Now().Add(-time.Hour),
	}).Error)

	p, err := h.CoreService.GetCompliancePosture(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, p.AccessGovernance.DormantRoleGrants, "alice accessed a secret recently — not dormant")
}

// #258: role grants must be assessed per grant, not per user — an admin-tier grant
// (secrets.delete + roles.assign, like the seeded "admin" role) must be flagged
// dormant even when the SAME user has recent, ordinary read activity under a
// separate, lower-tier grant (like "viewer") in the same project. Before this fix,
// countDormantRoleGrants asked only "did this user have ANY secret-access activity
// anywhere in the project", so the viewer grant's routine use masked a completely
// separate, unused admin-tier standing grant as "non-dormant".
func TestCompliancePosture_DormantRoleGrants_AdminTierGrantNotMaskedByReadActivity(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.AuditEvent{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.BreakGlassActivation{}, &models.RotationPolicy{},
	))

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	// alice holds both a read-tier grant (role 4, "viewer": secrets.read) and a
	// separate admin-tier grant (role 2, "admin": seeded with secrets.delete +
	// roles.assign among others) in the same project.
	h.AssignUserRole(t, 10, 4, uptr(proj))
	h.AssignUserRole(t, 10, 2, uptr(proj))

	// She reads secrets weekly — recent, ordinary activity exercising the viewer
	// grant — but never performs an admin-tier action (no role.assigned/removed or
	// secret.deleted) anywhere in this project.
	aid := uint(10)
	pid := proj
	require.NoError(t, h.DB.Create(&models.AuditEvent{
		EventType: "secret.read", UserID: &aid, ProjectID: &pid, EventTime: time.Now().Add(-time.Hour),
	}).Error)

	p, err := h.CoreService.GetCompliancePosture(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, p.AccessGovernance.DormantRoleGrants,
		"the unused admin-tier grant must be flagged dormant despite alice's recent read activity under the separate viewer grant")
}

// The companion case: once the admin-tier grant is actually exercised (a role
// assignment change attributed to alice, in the project), it's no longer dormant —
// demonstrating the fix distinguishes "used" from "unused" per grant rather than
// simply always requiring elevated activity.
func TestCompliancePosture_DormantRoleGrants_AdminTierGrantNotDormantWhenExercised(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.AuditEvent{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{}, &models.BreakGlassActivation{}, &models.RotationPolicy{},
	))

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 4, uptr(proj))
	h.AssignUserRole(t, 10, 2, uptr(proj))

	aid := uint(10)
	pid := proj
	require.NoError(t, h.DB.Create(&models.AuditEvent{
		EventType: "secret.read", UserID: &aid, ProjectID: &pid, EventTime: time.Now().Add(-time.Hour),
	}).Error)
	require.NoError(t, h.DB.Create(&models.AuditEvent{
		EventType: "role.assigned", UserID: &aid, ProjectID: &pid, EventTime: time.Now().Add(-time.Hour),
	}).Error)

	p, err := h.CoreService.GetCompliancePosture(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, p.AccessGovernance.DormantRoleGrants,
		"alice actually exercised the admin-tier grant — neither grant should be dormant")
}

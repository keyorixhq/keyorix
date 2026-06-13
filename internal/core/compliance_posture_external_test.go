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

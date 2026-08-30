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

// GenerateComplianceEvidence bundles the posture with its supporting records — the
// audit anchor, campaigns, and the break-glass register.
func TestGenerateComplianceEvidence_BundlesRecords(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(
		&models.AuditEvent{}, &models.AccessReviewCampaign{}, &models.AccessReviewItem{},
		&models.BreakGlassActivation{}, &models.RotationPolicy{},
	))

	const proj = uint(2)
	ctx := context.Background()
	h.CreateTestUser(t, "alice", 10)
	h.AssignUserRole(t, 10, 3, uptr(proj))

	// A campaign (the recertification record) and an active break-glass activation.
	camp, err := h.CoreService.OpenAccessReviewCampaign(ctx, 1, 0, proj, "Q4 review")
	require.NoError(t, err)
	future := time.Now().Add(time.Hour)
	require.NoError(t, h.DB.Create(&models.BreakGlassActivation{
		ProjectID: proj, UserID: 10, RoleID: 3, RoleName: "editor",
		Justification: "incident INC-1", State: "active", ExpiresAt: &future, CreatedAt: time.Now(),
	}).Error)

	ev, err := h.CoreService.GenerateComplianceEvidence(ctx)
	require.NoError(t, err)

	require.NotNil(t, ev.Posture, "the pack embeds the posture summary")

	// The campaign appears with its project and tally.
	var found bool
	for _, c := range ev.Campaigns {
		if c.ID == camp.Campaign.ID {
			found = true
			assert.Equal(t, proj, c.ProjectID)
			assert.Equal(t, "Q4 review", c.Name)
			assert.GreaterOrEqual(t, c.Total, 1)
		}
	}
	assert.True(t, found, "the campaign is in the evidence pack")

	// The break-glass activation is in the register.
	require.Len(t, ev.BreakGlass, 1)
	assert.Equal(t, "incident INC-1", ev.BreakGlass[0].Justification)

	// The audit anchor reflects the chained events (the campaign-opened audit).
	assert.GreaterOrEqual(t, ev.AuditAnchor.ChainedEvents, int64(1))
}

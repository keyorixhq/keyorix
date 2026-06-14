package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func hasOpenCampaign(campaigns []*core.CampaignWithProgress) bool {
	for _, c := range campaigns {
		if c.Campaign.State == core.CampaignStateOpen {
			return true
		}
	}
	return false
}

// A never-reviewed project with an admin gets one reminder; a second run does not
// re-notify (the admin still holds an unread one).
func TestRunScheduledRecertification_RemindsAndDedupes(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)
	require.NoError(t, h.DB.AutoMigrate(&models.Notification{}))

	ctx := context.Background()
	h.CreateTestUser(t, "carol", 20)
	h.AssignUserRole(t, 20, 2, uptr(2)) // admin on project 2 (role 2 = "admin")

	res, err := h.CoreService.RunScheduledRecertification(ctx, 90, false)
	require.NoError(t, err)
	assert.Equal(t, 0, res.Opened, "auto_open off → nothing opened")
	assert.GreaterOrEqual(t, res.Reminded, 1, "project 2's admin is reminded")

	// The admin holds an unread recertification reminder for project 2.
	notes, err := h.CoreService.Storage().ListNotifications(ctx, 20, true, 100)
	require.NoError(t, err)
	found := false
	for _, n := range notes {
		if n.Type == core.NotificationRecertificationDue && n.ProjectID != nil && *n.ProjectID == 2 {
			found = true
		}
	}
	assert.True(t, found, "carol has an unread recertification reminder for project 2")

	res2, err := h.CoreService.RunScheduledRecertification(ctx, 90, false)
	require.NoError(t, err)
	assert.Equal(t, 0, res2.Reminded, "an unread reminder suppresses a duplicate")
}

// With auto_open on, an overdue project (last campaign closed > cadence ago) gets a
// fresh open campaign, while a recently-reviewed project does not.
func TestRunScheduledRecertification_AutoOpensOverdueNotRecent(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	migrateCampaignTables(t, h)
	require.NoError(t, h.DB.AutoMigrate(&models.Notification{}))

	ctx := context.Background()
	now := time.Now()
	oldClosed := now.AddDate(0, 0, -200)   // overdue under a 90-day cadence
	recentClosed := now.AddDate(0, 0, -10) // within the cadence

	require.NoError(t, h.DB.Create(&models.AccessReviewCampaign{
		ProjectID: 2, Name: "old", State: core.CampaignStateClosed, ClosedAt: &oldClosed,
	}).Error)
	require.NoError(t, h.DB.Create(&models.AccessReviewCampaign{
		ProjectID: 3, Name: "recent", State: core.CampaignStateClosed, ClosedAt: &recentClosed,
	}).Error)

	res, err := h.CoreService.RunScheduledRecertification(ctx, 90, true)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, res.Opened, 1)

	camps2, err := h.CoreService.ListAccessReviewCampaigns(ctx, 2)
	require.NoError(t, err)
	assert.True(t, hasOpenCampaign(camps2), "overdue project 2 gets a fresh open campaign")

	camps3, err := h.CoreService.ListAccessReviewCampaigns(ctx, 3)
	require.NoError(t, err)
	assert.False(t, hasOpenCampaign(camps3), "recently-reviewed project 3 is left alone")
}

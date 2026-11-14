// dashboard_stats_activity_noise_test.go — #4272: GET /dashboard/stats built its
// recentActivity without the #4184 filter, so the scheduler's "job ran"
// heartbeats (admin_job.*, actor system, every 15 s) reached API/SDK consumers.
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetDashboardStats_RecentActivityHidesSchedulerHeartbeats(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	adminID := seedUserWithRole(t, st, "statsadmin", "system_admin", storage.Scope{})

	// Start from an empty audit log so only the rows below count.
	require.NoError(t, st.DB().Where("1 = 1").Delete(&models.AuditEvent{}).Error)

	uid := adminID
	c.writeAuditEvent(ctx, "role.removed", &uid, nil, "role removed by statsadmin")
	c.writeAuditEvent(ctx, "role.assigned", &uid, nil, "role assigned by statsadmin")
	// More scheduler heartbeats than the card's page size, written after the user
	// events, so an unfiltered page of newest rows holds nothing but heartbeats.
	for range dashboardRecentActivity + 1 {
		_, err := c.AlertNewAnomalies(ctx)
		require.NoError(t, err)
	}

	stats, err := c.GetDashboardStats(ctx, adminID, "statsadmin", adminID)
	require.NoError(t, err)

	got := eventTypes(stats.RecentActivity)
	assert.ElementsMatch(t, []string{"role.removed", "role.assigned"}, got,
		"recentActivity must hold only the user events, no admin_job.* heartbeats: %v", got)
}

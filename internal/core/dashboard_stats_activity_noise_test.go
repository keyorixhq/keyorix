// dashboard_stats_activity_noise_test.go — #4272: GET /dashboard/stats builds its own
// recentActivity array (separate from the activity feed #4184 fixed), so API and SDK
// consumers saw the scheduler's admin_job.anomaly_alerts_run heartbeat every 15 s.
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetDashboardStats_RecentActivityHidesSchedulerHeartbeats(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	auditorID := seedUserWithRole(t, st, "auditor7", "system_auditor", storage.Scope{})

	// The scheduler's clean pass (actor system, no user), then a real user action
	// written after it so it is the newest row and the heartbeat sits inside the
	// page of five the stats feed reads.
	_, err := c.AlertNewAnomalies(ctx)
	require.NoError(t, err)
	c.writeAuditEvent(ctx, "role.removed", &auditorID, nil, "role removed by auditor7")

	// Precondition: the heartbeat row really is stored, so the assertion below
	// cannot pass just because nothing was written.
	logs, _, err := st.GetAuditLogs(ctx, &storage.AuditFilter{PageSize: 50})
	require.NoError(t, err)
	var stored []string
	for _, e := range logs {
		stored = append(stored, e.EventType)
	}
	require.Contains(t, stored, "admin_job.anomaly_alerts_run")

	stats, err := c.GetDashboardStats(ctx, auditorID, "auditor7", auditorID)
	require.NoError(t, err)

	got := eventTypes(stats.RecentActivity)
	assert.Contains(t, got, "role.removed")
	assert.NotContains(t, got, "admin_job.anomaly_alerts_run",
		"the stats recentActivity feed must hide scheduler heartbeats like the activity feed does: %v", got)
}

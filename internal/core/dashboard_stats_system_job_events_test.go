package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #4272: GET /dashboard/stats recentActivity must not list the scheduler's own
// admin_job.* heartbeats. #4184 filtered /dashboard/activity only; the stats feed
// is a second audit query and kept showing them.

// statsFeedBackends runs fn on SQLite (always) and Postgres (when
// KEYORIX_TEST_PG_DSN is set; otherwise the subtest skips).
func statsFeedBackends(t *testing.T, fn func(t *testing.T, f *ctaReview)) {
	t.Run("sqlite", func(t *testing.T) { fn(t, newCTAReviewSQLite(t)) })
	t.Run("postgres", func(t *testing.T) { fn(t, newCTAReview(t)) })
}

// statsFeedClearAudit drops the bootstrap/setup audit rows so recentActivity holds
// only what the test seeds.
func statsFeedClearAudit(t *testing.T, f *ctaReview) {
	t.Helper()
	require.NoError(t, f.dbA.Exec("DELETE FROM audit_events").Error)
}

func statsFeedEventTypes(items []ActivityItem) []string {
	got := make([]string, 0, len(items))
	for _, it := range items {
		got = append(got, it.EventType)
	}
	return got
}

func TestGetDashboardStats_RecentActivityExcludesSystemJobHeartbeats(t *testing.T) {
	statsFeedBackends(t, func(t *testing.T, f *ctaReview) {
		ctx := context.Background()
		statsFeedClearAudit(t, f)
		now := time.Now().UTC()
		for i := range 5 {
			require.NoError(t, f.dbA.Exec(
				"INSERT INTO audit_events (event_type, actor_type, event_time) VALUES ('admin_job.anomaly_alerts_run', 'system', ?)",
				now.Add(time.Duration(10+i)*time.Second)).Error)
		}
		require.NoError(t, f.dbA.Exec(
			"INSERT INTO audit_events (event_type, actor_type, user_id, event_time) VALUES ('role.removed', 'user', ?, ?)",
			f.adminID, now.Add(1*time.Second)).Error)
		require.NoError(t, f.dbA.Exec(
			"INSERT INTO audit_events (event_type, actor_type, user_id, event_time) VALUES ('secret.created', 'user', ?, ?)",
			f.adminID, now.Add(2*time.Second)).Error)

		stats, err := f.coreA.GetDashboardStats(ctx, f.adminID, "admin", f.adminID)
		require.NoError(t, err)
		assert.Equal(t, []string{"secret.created", "role.removed"}, statsFeedEventTypes(stats.RecentActivity),
			"heartbeats must not reach recentActivity, and must not push real events out of it")
	})
}

// A legacy user row with actor_type NULL that happens to be an admin_job.* type
// is kind user, so the filter keeps it (see
// internal/storage/store/audit_exclude_system_job_events_test.go).
func TestGetDashboardStats_RecentActivityKeepsNullActorTypeUserRow(t *testing.T) {
	statsFeedBackends(t, func(t *testing.T, f *ctaReview) {
		ctx := context.Background()
		statsFeedClearAudit(t, f)
		now := time.Now().UTC()
		require.NoError(t, f.dbA.Exec(
			"INSERT INTO audit_events (event_type, actor_type, event_time) VALUES ('admin_job.anomaly_alerts_run', 'system', ?)",
			now.Add(3*time.Second)).Error)
		require.NoError(t, f.dbA.Exec(
			"INSERT INTO audit_events (event_type, actor_type, user_id, event_time) VALUES ('admin_job.legacy_user_run', NULL, ?, ?)",
			f.adminID, now.Add(2*time.Second)).Error)
		require.NoError(t, f.dbA.Exec(
			"INSERT INTO audit_events (event_type, actor_type, user_id, event_time) VALUES ('role.removed', 'user', ?, ?)",
			f.adminID, now.Add(1*time.Second)).Error)

		stats, err := f.coreA.GetDashboardStats(ctx, f.adminID, "admin", f.adminID)
		require.NoError(t, err)
		assert.Equal(t, []string{"admin_job.legacy_user_run", "role.removed"}, statsFeedEventTypes(stats.RecentActivity))
	})
}

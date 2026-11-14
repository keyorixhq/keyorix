// dashboard_activity_noise_test.go — #4184: the dashboard "Recent Activity" feed
// must show what people and machines did, not the scheduler's "job ran"
// heartbeats. The audit log itself keeps every row.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/sqlitetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newActivityFeedCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db := sqlitetest.OpenWithDialector(t, "activityfeed_", sqlite.Open, &gorm.Config{})
	require.NoError(t, db.AutoMigrate(&models.User{}, &models.SecretNode{}, &models.AnomalyAlert{}, &models.AuditEvent{}, &models.MachineIdentity{}))
	require.NoError(t, db.Create(&models.User{ID: 5, Username: "ada", Email: "ada@x.io", IsActive: true}).Error)
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	return &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}, db
}

func eventTypes(items []ActivityItem) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.EventType)
	}
	return out
}

func TestGetActivityFeed_HidesSchedulerHeartbeats_KeepsAdminTriggeredRuns(t *testing.T) {
	c, db := newActivityFeedCore(t)
	ctx := context.Background()

	uid := uint(5)
	c.writeAuditEvent(ctx, "role.removed", &uid, nil, "role removed by ada")
	// The scheduler's clean pass: actor system, no user.
	_, err := c.AlertNewAnomalies(ctx)
	require.NoError(t, err)
	_, err = c.AlertNewAnomalies(ctx)
	require.NoError(t, err)
	// An admin forcing the same job on demand is a human action and stays.
	_, err = c.AlertNewAnomalies(WithAuditActor(ctx, uid))
	require.NoError(t, err)

	feed, err := c.GetActivityFeed(ctx, 1, "viewer", 1, 50)
	require.NoError(t, err)
	got := eventTypes(feed.Items)
	assert.Contains(t, got, "role.removed")
	assert.Equal(t, 1, countOf(got, "admin_job.anomaly_alerts_run"),
		"only the admin-triggered run stays; the two scheduler heartbeats are hidden: %v", got)
	assert.EqualValues(t, 2, feed.Total, "total must agree with the filtered list so paging stays correct")

	// The audit log still lists every row that exists.
	_, all, err := c.storage.GetAuditLogs(ctx, &storage.AuditFilter{PageSize: 50})
	require.NoError(t, err)
	assert.EqualValues(t, 4, all)
	var heartbeats int64
	require.NoError(t, db.Model(&models.AuditEvent{}).
		Where("event_type = ? AND actor_type = ?", "admin_job.anomaly_alerts_run", ActorTypeSystem).Count(&heartbeats).Error)
	assert.EqualValues(t, 2, heartbeats)
}

func countOf(ss []string, want string) int {
	n := 0
	for _, s := range ss {
		if s == want {
			n++
		}
	}
	return n
}

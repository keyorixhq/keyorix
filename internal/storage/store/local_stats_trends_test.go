// local_stats_trends_test.go — tests for SaveDeploymentStatsSnapshot and
// GetPreviousDeploymentStatsSnapshot in LocalStorage.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveAndGetPreviousDeploymentStatsSnapshot(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "depl_snap_"+t.Name(), &models.DeploymentStatsSnapshot{})

	// Save a snapshot 2 days ago (well outside the 20-hour cutoff).
	twoDaysAgo := time.Now().UTC().Add(-48 * time.Hour)
	snap := &models.DeploymentStatsSnapshot{
		ActiveUsers:    10,
		AuditEvents30d: 200,
		SnapshotDate:   twoDaysAgo,
	}
	require.NoError(t, ls.SaveDeploymentStatsSnapshot(ctx, snap))

	got, err := ls.GetPreviousDeploymentStatsSnapshot(ctx)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, int64(10), got.ActiveUsers)
	assert.Equal(t, int64(200), got.AuditEvents30d)
}

func TestGetPreviousDeploymentStatsSnapshot_RecentSnapshotExcluded(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "depl_snap_recent_"+t.Name(), &models.DeploymentStatsSnapshot{})

	// Save a snapshot 10 hours ago — inside the 20-hour cutoff, should be excluded.
	tenHoursAgo := time.Now().UTC().Add(-10 * time.Hour)
	snap := &models.DeploymentStatsSnapshot{
		ActiveUsers:    5,
		AuditEvents30d: 100,
		SnapshotDate:   tenHoursAgo,
	}
	require.NoError(t, ls.SaveDeploymentStatsSnapshot(ctx, snap))

	got, err := ls.GetPreviousDeploymentStatsSnapshot(ctx)
	require.NoError(t, err)
	assert.Nil(t, got, "a snapshot within the 20-hour window must not be returned")
}

func TestGetPreviousDeploymentStatsSnapshot_Empty(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "depl_snap_empty_"+t.Name(), &models.DeploymentStatsSnapshot{})

	got, err := ls.GetPreviousDeploymentStatsSnapshot(ctx)
	require.NoError(t, err)
	assert.Nil(t, got, "no snapshots → should return nil, nil")
}

func TestGetPreviousDeploymentStatsSnapshot_ReturnsLatestOlderThan20h(t *testing.T) {
	ctx := context.Background()
	ls := newStoreS3(t, "depl_snap_latest_"+t.Name(), &models.DeploymentStatsSnapshot{})

	// Save two snapshots both older than 20 hours; the more recent one (2 days ago)
	// should be returned, not the older one (5 days ago).
	twoDaysAgo := time.Now().UTC().Add(-48 * time.Hour)
	fiveDaysAgo := time.Now().UTC().Add(-5 * 24 * time.Hour)

	require.NoError(t, ls.SaveDeploymentStatsSnapshot(ctx, &models.DeploymentStatsSnapshot{
		ActiveUsers:    3,
		AuditEvents30d: 50,
		SnapshotDate:   fiveDaysAgo,
	}))
	require.NoError(t, ls.SaveDeploymentStatsSnapshot(ctx, &models.DeploymentStatsSnapshot{
		ActiveUsers:    8,
		AuditEvents30d: 150,
		SnapshotDate:   twoDaysAgo,
	}))

	got, err := ls.GetPreviousDeploymentStatsSnapshot(ctx)
	require.NoError(t, err)
	require.NotNil(t, got)
	// Should return the more recent one (2 days ago), not the 5-days-ago one.
	assert.Equal(t, int64(8), got.ActiveUsers, "expected the most recent eligible snapshot")
	assert.Equal(t, int64(150), got.AuditEvents30d)
}

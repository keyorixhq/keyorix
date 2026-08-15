// dashboard_trends_test.go — tests for deployment-wide trend indicators on
// GetDashboardStats (ActiveUsersTrend, AuditEvents30dTrend).
package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDashboardTrends_NoPreviousSnapshot_NoTrend verifies that when no previous
// deployment snapshot exists the trend fields are nil (not a false "0% change").
func TestDashboardTrends_NoPreviousSnapshot_NoTrend(t *testing.T) {
	c, st := newBootstrappedCore(t)
	auditorID := seedUserWithRole(t, st, "trend_auditor1", "system_auditor", storage.Scope{})

	stats, err := c.GetDashboardStats(context.Background(), auditorID, "trend_auditor1", auditorID)
	require.NoError(t, err)

	assert.Nil(t, stats.ActiveUsersTrend, "no previous snapshot → ActiveUsersTrend must be nil")
	assert.Nil(t, stats.AuditEvents30dTrend, "no previous snapshot → AuditEvents30dTrend must be nil")
	assert.Nil(t, stats.AuditLogins30dTrend, "no previous snapshot → AuditLogins30dTrend must be nil")
	assert.Nil(t, stats.AuditSecretReads30dTrend, "no previous snapshot → AuditSecretReads30dTrend must be nil")
	assert.Nil(t, stats.FailedAuthAttempts24hTrend, "no previous snapshot → FailedAuthAttempts24hTrend must be nil")
	assert.Nil(t, stats.InactiveUsersTrend, "no previous snapshot → InactiveUsersTrend must be nil")
}

// TestDashboardTrends_WithPreviousSnapshot_ComputesTrend verifies that when a
// previous deployment snapshot exists the trend is computed correctly.
func TestDashboardTrends_WithPreviousSnapshot_ComputesTrend(t *testing.T) {
	c, st := newBootstrappedCore(t)
	auditorID := seedUserWithRole(t, st, "trend_auditor2", "system_auditor", storage.Scope{})

	// Seed a deployment snapshot 2 days ago (well outside the 20-hour cutoff) with
	// fewer active users and fewer audit events than there will be now.
	twoDaysAgo := time.Now().UTC().Add(-48 * time.Hour)
	err := st.SaveDeploymentStatsSnapshot(context.Background(), &models.DeploymentStatsSnapshot{
		ActiveUsers:           1, // will grow: BootstrapSystem already created "admin" + we added "trend_auditor2"
		AuditEvents30d:        0,
		AuditLogins30d:        0,
		AuditSecretReads30d:   0,
		FailedAuthAttempts24h: 0,
		InactiveUsers:         0,
		SnapshotDate:          twoDaysAgo,
	})
	require.NoError(t, err)

	stats, err := c.GetDashboardStats(context.Background(), auditorID, "trend_auditor2", auditorID)
	require.NoError(t, err)

	// After BootstrapSystem there is at least 1 user (admin) + trend_auditor2 = ≥2 users.
	// The stored previous value was 1, so active users grew → IsPositive should be true.
	require.NotNil(t, stats.PrevActiveUsers, "PrevActiveUsers must be set when a previous snapshot exists")
	assert.Equal(t, int64(1), *stats.PrevActiveUsers)

	if stats.ActiveUsers > 1 {
		// Growth case: trend should be positive.
		require.NotNil(t, stats.ActiveUsersTrend, "ActiveUsersTrend must be computed when prev != current")
		assert.True(t, stats.ActiveUsersTrend.IsPositive, "users grew from 1 → IsPositive must be true")
	}
	// PrevAuditEvents30d is always set when prevSnap != nil.
	require.NotNil(t, stats.PrevAuditEvents30d)

	// New fields must also be set when prevSnap != nil.
	require.NotNil(t, stats.PrevAuditLogins30d, "PrevAuditLogins30d must be set")
	assert.Equal(t, int64(0), *stats.PrevAuditLogins30d)
	require.NotNil(t, stats.PrevAuditSecretReads30d, "PrevAuditSecretReads30d must be set")
	assert.Equal(t, int64(0), *stats.PrevAuditSecretReads30d)
	require.NotNil(t, stats.PrevFailedAuthAttempts24h, "PrevFailedAuthAttempts24h must be set")
	assert.Equal(t, int64(0), *stats.PrevFailedAuthAttempts24h)
	require.NotNil(t, stats.PrevInactiveUsers, "PrevInactiveUsers must be set")
	assert.Equal(t, int64(0), *stats.PrevInactiveUsers)
}

// TestDashboardTrends_SnapshotSavedAfterAdminCall verifies that the first call
// saves a deployment snapshot so that the second call can pick it up as "previous".
func TestDashboardTrends_SnapshotSavedAfterAdminCall(t *testing.T) {
	c, st := newBootstrappedCore(t)
	auditorID := seedUserWithRole(t, st, "trend_auditor3", "system_auditor", storage.Scope{})

	// First call: no previous snapshot yet, so PrevActiveUsers must be nil.
	stats1, err := c.GetDashboardStats(context.Background(), auditorID, "trend_auditor3", auditorID)
	require.NoError(t, err)
	assert.Nil(t, stats1.PrevActiveUsers, "first call: no previous snapshot → PrevActiveUsers must be nil")

	// Manually backdate the snapshot saved by the first call so the second call's
	// 20-hour cutoff treats it as "previous". We access the underlying *gorm.DB
	// via st.DB() (a test-only accessor) to set a past snapshot_date directly.
	err = st.DB().WithContext(context.Background()).
		Model(&models.DeploymentStatsSnapshot{}).
		Where("1 = 1").
		Update("snapshot_date", time.Now().UTC().Add(-48*time.Hour)).Error
	require.NoError(t, err)

	// Second call: should find the backdated snapshot and populate PrevActiveUsers.
	stats2, err := c.GetDashboardStats(context.Background(), auditorID, "trend_auditor3", auditorID)
	require.NoError(t, err)

	require.NotNil(t, stats2.PrevActiveUsers, "second call must find the snapshot from the first call")
	assert.Equal(t, stats1.ActiveUsers, *stats2.PrevActiveUsers,
		"PrevActiveUsers on the second call must equal ActiveUsers from the first call")
}

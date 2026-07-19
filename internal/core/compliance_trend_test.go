package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// complianceTrendCore builds a KeyorixCore backed by a sqlite DB that has both the
// minimal tables GetCompliancePosture needs (Project, to avoid a fatal error on
// ListProjects) and CompliancePostureSnapshot (for the trend machinery).
// Additional tables left unmigrated degrade the posture sub-rollups gracefully.
func complianceTrendCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Project{},
		&models.CompliancePostureSnapshot{},
	))
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}
	c.now = func() time.Time { return time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC) }
	return c, db
}

// TestGetCompliancePosture_TrendNoData verifies that the first call with no prior
// snapshot returns a Trend with Direction "no_data".
func TestGetCompliancePosture_TrendNoData(t *testing.T) {
	c, _ := complianceTrendCore(t)

	p, err := c.GetCompliancePosture(context.Background())
	require.NoError(t, err)

	require.NotNil(t, p.Trend, "Trend must be populated even on first call")
	assert.Equal(t, "no_data", p.Trend.Direction)
	assert.Nil(t, p.Trend.PreviousDate, "PreviousDate must be nil when no prior snapshot exists")
	assert.Nil(t, p.Trend.PassedDelta, "PassedDelta must be nil when there is no prior data")
	assert.Nil(t, p.Trend.FailedDelta, "FailedDelta must be nil when there is no prior data")
}

// TestGetCompliancePosture_TrendImproving verifies that when the previous snapshot
// had fewer passed controls than the current one, Direction = "improving".
func TestGetCompliancePosture_TrendImproving(t *testing.T) {
	c, db := complianceTrendCore(t)
	ctx := context.Background()

	// Seed a prior snapshot with only 5 passed controls — older than 20 hours so it
	// qualifies as a "previous" snapshot.
	prevDate := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC) // two days ago
	require.NoError(t, db.Create(&models.CompliancePostureSnapshot{
		TotalControls:  15,
		PassedControls: 5,
		FailedControls: 8,
		SnapshotDate:   prevDate,
	}).Error)

	p, err := c.GetCompliancePosture(ctx)
	require.NoError(t, err)

	require.NotNil(t, p.Trend)
	assert.Equal(t, "improving", p.Trend.Direction,
		"more controls passing now than in the prior snapshot → improving")
	require.NotNil(t, p.Trend.PassedDelta)
	assert.Greater(t, *p.Trend.PassedDelta, 0,
		"PassedDelta must be positive when more controls are passing now")
	require.NotNil(t, p.Trend.PreviousDate)
	assert.Equal(t, prevDate, *p.Trend.PreviousDate)
}

// TestGetCompliancePosture_TrendStable verifies that when the passed-control and
// failed-control counts are identical to the prior snapshot, Direction = "stable".
func TestGetCompliancePosture_TrendStable(t *testing.T) {
	c, db := complianceTrendCore(t)
	ctx := context.Background()

	// First, run a call to discover the actual counts this core produces so we can
	// seed a matching prior snapshot.
	p1, err := c.GetCompliancePosture(ctx)
	require.NoError(t, err)
	require.NotNil(t, p1.Trend)
	// p1.Trend.Direction is "no_data" (no prior snapshot existed for this first call).

	// Now retrieve the snapshot that was just saved.
	var savedSnap models.CompliancePostureSnapshot
	require.NoError(t, db.First(&savedSnap).Error)

	// Seed an older snapshot with the SAME passed/failed counts, dated 48 hours
	// before the fixed clock so it falls outside the 20-hour window.
	olderDate := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)
	require.NoError(t, db.Create(&models.CompliancePostureSnapshot{
		TotalControls:    savedSnap.TotalControls,
		PassedControls:   savedSnap.PassedControls,
		FailedControls:   savedSnap.FailedControls,
		DegradedControls: savedSnap.DegradedControls,
		SnapshotDate:     olderDate,
	}).Error)

	// Delete the snapshot for today so the second call produces a fresh save that
	// will compare against our older seed row.
	require.NoError(t, db.Delete(&savedSnap).Error)

	p2, err := c.GetCompliancePosture(ctx)
	require.NoError(t, err)
	require.NotNil(t, p2.Trend)
	assert.Equal(t, "stable", p2.Trend.Direction,
		"identical passed/failed counts → stable")
	require.NotNil(t, p2.Trend.PassedDelta)
	assert.Equal(t, 0, *p2.Trend.PassedDelta)
	require.NotNil(t, p2.Trend.FailedDelta)
	assert.Equal(t, 0, *p2.Trend.FailedDelta)
}

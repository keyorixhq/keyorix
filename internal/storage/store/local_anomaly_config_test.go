package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newAnomalyConfigTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.AnomalyConfigRecord{}))
	return NewLocalStorage(db)
}

// TestGetAnomalyConfig_ReturnsDefaultWhenNoRow checks that an empty DB returns
// sensible defaults without an error.
func TestGetAnomalyConfig_ReturnsDefaultWhenNoRow(t *testing.T) {
	ctx := context.Background()
	ls := newAnomalyConfigTestStore(t)

	cfg, err := ls.GetAnomalyConfig(ctx)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, 7, cfg.LookbackDays, "default lookback should be 7 days")
	assert.Equal(t, 24, cfg.QuarantineHours, "default quarantine should be 24 hours")
	assert.False(t, cfg.MLEnabled, "ML should be disabled by default")
	assert.Equal(t, 0.6, cfg.MLThreshold)
	assert.Equal(t, 100, cfg.MLNumTrees)
	assert.Equal(t, 256, cfg.MLSampleSize)
}

// TestSaveAndGetAnomalyConfig_RoundTrip verifies that a saved config survives
// a round-trip through the DB unchanged.
func TestSaveAndGetAnomalyConfig_RoundTrip(t *testing.T) {
	ctx := context.Background()
	ls := newAnomalyConfigTestStore(t)

	want := &models.AnomalyConfigRecord{
		LookbackDays:     14,
		QuarantineHours:  48,
		OffHoursEnabled:  true,
		OffHoursTimezone: "America/New_York",
		OffHoursStart:    20,
		OffHoursEnd:      8,
		MLEnabled:        true,
		MLThreshold:      0.75,
		MLNumTrees:       200,
		MLSampleSize:     512,
		UpdatedBy:        "alice",
		UpdatedAt:        time.Now().Truncate(time.Second),
	}
	require.NoError(t, ls.SaveAnomalyConfig(ctx, want))

	got, err := ls.GetAnomalyConfig(ctx)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, 14, got.LookbackDays)
	assert.Equal(t, 48, got.QuarantineHours)
	assert.True(t, got.OffHoursEnabled)
	assert.Equal(t, "America/New_York", got.OffHoursTimezone)
	assert.Equal(t, 20, got.OffHoursStart)
	assert.Equal(t, 8, got.OffHoursEnd)
	assert.True(t, got.MLEnabled)
	assert.InDelta(t, 0.75, got.MLThreshold, 1e-9)
	assert.Equal(t, 200, got.MLNumTrees)
	assert.Equal(t, 512, got.MLSampleSize)
	assert.Equal(t, "alice", got.UpdatedBy)
}

// TestSaveAnomalyConfig_Singleton ensures that calling SaveAnomalyConfig twice
// results in exactly one row (the second call upserts, not appends).
func TestSaveAnomalyConfig_Singleton(t *testing.T) {
	ctx := context.Background()
	ls := newAnomalyConfigTestStore(t)

	first := &models.AnomalyConfigRecord{LookbackDays: 3, UpdatedBy: "alice"}
	require.NoError(t, ls.SaveAnomalyConfig(ctx, first))

	second := &models.AnomalyConfigRecord{LookbackDays: 14, UpdatedBy: "bob"}
	require.NoError(t, ls.SaveAnomalyConfig(ctx, second))

	// Only one row should exist.
	var count int64
	ls.db.Model(&models.AnomalyConfigRecord{}).Count(&count)
	assert.Equal(t, int64(1), count, "SaveAnomalyConfig must maintain a single row")

	// And it should reflect the latest save.
	got, err := ls.GetAnomalyConfig(ctx)
	require.NoError(t, err)
	assert.Equal(t, 14, got.LookbackDays)
	assert.Equal(t, "bob", got.UpdatedBy)
}

// TestGetAnomalyConfig_ReturnsUpdatedValues verifies that after saving, the
// next Get reflects the new values (not the old defaults).
func TestGetAnomalyConfig_ReturnsUpdatedValues(t *testing.T) {
	ctx := context.Background()
	ls := newAnomalyConfigTestStore(t)

	// First Get returns defaults.
	def, err := ls.GetAnomalyConfig(ctx)
	require.NoError(t, err)
	assert.Equal(t, 7, def.LookbackDays)

	// Save a non-default value.
	require.NoError(t, ls.SaveAnomalyConfig(ctx, &models.AnomalyConfigRecord{LookbackDays: 30}))

	// Next Get reflects the persisted value, not the hard-coded default.
	got, err := ls.GetAnomalyConfig(ctx)
	require.NoError(t, err)
	assert.Equal(t, 30, got.LookbackDays)
}

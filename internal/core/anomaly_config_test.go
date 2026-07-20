package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newAnomalyConfigCore(store *MockStorage) *KeyorixCore {
	return &KeyorixCore{storage: store}
}

func TestGetAnomalyConfig_DelegatesToStorage(t *testing.T) {
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	want := &models.AnomalyConfigRecord{LookbackDays: 14, QuarantineHours: 48}
	store.On("GetAnomalyConfig", ctx).Return(want, nil)

	got, err := c.GetAnomalyConfig(ctx)
	require.NoError(t, err)
	assert.Equal(t, 14, got.LookbackDays)
	assert.Equal(t, 48, got.QuarantineHours)
}

func TestGetAnomalyConfig_PropagatesError(t *testing.T) {
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	store.On("GetAnomalyConfig", ctx).Return(nil, errors.New("db error"))

	_, err := c.GetAnomalyConfig(ctx)
	require.Error(t, err)
}

func TestUpdateAnomalyConfig_SetsUpdatedByAndDelegatesToStorage(t *testing.T) {
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	cfg := &models.AnomalyConfigRecord{LookbackDays: 30}
	store.On("SaveAnomalyConfig", ctx, mock.MatchedBy(func(r *models.AnomalyConfigRecord) bool {
		return r.UpdatedBy == "admin" && r.LookbackDays == 30
	})).Return(nil)

	err := c.UpdateAnomalyConfig(ctx, cfg, "admin")
	require.NoError(t, err)
	assert.Equal(t, "admin", cfg.UpdatedBy)
	assert.False(t, cfg.UpdatedAt.IsZero())
}

func TestUpdateAnomalyConfig_PropagatesStorageError(t *testing.T) {
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	cfg := &models.AnomalyConfigRecord{}
	store.On("SaveAnomalyConfig", ctx, mock.AnythingOfType("*models.AnomalyConfigRecord")).
		Return(errors.New("write failed"))

	err := c.UpdateAnomalyConfig(ctx, cfg, "user")
	require.Error(t, err)
}

func TestApplyAnomalyConfig_SetsLookback(t *testing.T) {
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	cfg := &models.AnomalyConfigRecord{LookbackDays: 14}
	store.On("GetAnomalyConfig", ctx).Return(cfg, nil)

	detector := NewAnomalyDetector(store)
	err := c.ApplyAnomalyConfig(ctx, detector)
	require.NoError(t, err)
	assert.Equal(t, 14*24*time.Hour, detector.lookback)
}

func TestApplyAnomalyConfig_SetsQuarantine(t *testing.T) {
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	cfg := &models.AnomalyConfigRecord{QuarantineHours: 48}
	store.On("GetAnomalyConfig", ctx).Return(cfg, nil)

	detector := NewAnomalyDetector(store)
	err := c.ApplyAnomalyConfig(ctx, detector)
	require.NoError(t, err)
	assert.Equal(t, 48*time.Hour, detector.quarantine)
}

func TestApplyAnomalyConfig_SetsMLConfig(t *testing.T) {
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	cfg := &models.AnomalyConfigRecord{
		MLEnabled:    true,
		MLThreshold:  0.75,
		MLNumTrees:   100,
		MLSampleSize: 256,
	}
	store.On("GetAnomalyConfig", ctx).Return(cfg, nil)

	detector := NewAnomalyDetector(store)
	err := c.ApplyAnomalyConfig(ctx, detector)
	require.NoError(t, err)
	assert.True(t, detector.ml.Enabled)
	assert.Equal(t, 0.75, detector.ml.Threshold)
	assert.Equal(t, 100, detector.ml.NumTrees)
}

func TestApplyAnomalyConfig_ZeroValuesNotApplied(t *testing.T) {
	// LookbackDays=0 and QuarantineHours=0 should not override detector defaults.
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	cfg := &models.AnomalyConfigRecord{LookbackDays: 0, QuarantineHours: 0}
	store.On("GetAnomalyConfig", ctx).Return(cfg, nil)

	detector := NewAnomalyDetector(store)
	originalLookback := detector.lookback
	originalQuarantine := detector.quarantine

	err := c.ApplyAnomalyConfig(ctx, detector)
	require.NoError(t, err)
	assert.Equal(t, originalLookback, detector.lookback)
	assert.Equal(t, originalQuarantine, detector.quarantine)
}

func TestApplyAnomalyConfig_PropagatesGetError(t *testing.T) {
	store := new(MockStorage)
	c := newAnomalyConfigCore(store)
	ctx := context.Background()

	store.On("GetAnomalyConfig", ctx).Return(nil, errors.New("db error"))

	detector := NewAnomalyDetector(store)
	err := c.ApplyAnomalyConfig(ctx, detector)
	require.Error(t, err)
}

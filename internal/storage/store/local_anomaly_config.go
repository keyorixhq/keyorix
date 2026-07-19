package store

import (
	"context"
	"errors"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// defaultAnomalyConfig returns sensible defaults matching the current startup values.
func defaultAnomalyConfig() *models.AnomalyConfigRecord {
	return &models.AnomalyConfigRecord{
		ID:               1,
		LookbackDays:     7,
		QuarantineHours:  24,
		OffHoursEnabled:  false,
		OffHoursTimezone: "UTC",
		OffHoursStart:    22,
		OffHoursEnd:      6,
		MLEnabled:        false,
		MLThreshold:      0.6,
		MLNumTrees:       100,
		MLSampleSize:     256,
		UpdatedAt:        time.Now(),
	}
}

// GetAnomalyConfig retrieves the single anomaly config row (ID=1), or returns
// sensible defaults if no row has been saved yet.
func (ls *LocalStorage) GetAnomalyConfig(ctx context.Context) (*models.AnomalyConfigRecord, error) {
	var cfg models.AnomalyConfigRecord
	err := ls.db.WithContext(ctx).First(&cfg, 1).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return defaultAnomalyConfig(), nil
	}
	return &cfg, err
}

// SaveAnomalyConfig upserts the singleton anomaly config (always ID=1).
func (ls *LocalStorage) SaveAnomalyConfig(ctx context.Context, cfg *models.AnomalyConfigRecord) error {
	cfg.ID = 1 // always singleton
	return ls.db.WithContext(ctx).Save(cfg).Error
}

package core

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ApplyAnomalyConfig loads the persisted anomaly config and applies it to the
// given detector. Call at startup and before each detection scan so runtime
// changes take effect without a restart.
func (c *KeyorixCore) ApplyAnomalyConfig(ctx context.Context, detector *AnomalyDetector) error {
	cfg, err := c.storage.GetAnomalyConfig(ctx)
	if err != nil {
		return err
	}

	// Lookback
	if cfg.LookbackDays > 0 {
		detector.SetLookback(time.Duration(cfg.LookbackDays) * 24 * time.Hour)
	}
	// Quarantine
	if cfg.QuarantineHours > 0 {
		detector.SetBaselineQuarantine(time.Duration(cfg.QuarantineHours) * time.Hour)
	}
	// Off-hours (only applied when enabled; the detector keeps its own default when disabled)
	if cfg.OffHoursEnabled {
		_ = detector.SetBusinessHours(ctx, cfg.OffHoursTimezone, cfg.OffHoursStart, cfg.OffHoursEnd)
	}
	// ML
	detector.SetMLConfig(MLConfig{
		Enabled:    cfg.MLEnabled,
		Threshold:  cfg.MLThreshold,
		NumTrees:   cfg.MLNumTrees,
		SampleSize: cfg.MLSampleSize,
	})
	return nil
}

// GetAnomalyConfig returns the current persisted anomaly detection config (or
// sensible defaults if none has been saved yet).
func (c *KeyorixCore) GetAnomalyConfig(ctx context.Context) (*models.AnomalyConfigRecord, error) {
	return c.storage.GetAnomalyConfig(ctx)
}

// UpdateAnomalyConfig persists a new anomaly detection config.  updatedBy is
// the username of the operator making the change (stored on the row for audit
// purposes); the caller is responsible for applying the new config to the live
// detector via ApplyAnomalyConfig if one is running.
func (c *KeyorixCore) UpdateAnomalyConfig(ctx context.Context, cfg *models.AnomalyConfigRecord, updatedBy string) error {
	cfg.UpdatedBy = updatedBy
	cfg.UpdatedAt = time.Now()
	return c.storage.SaveAnomalyConfig(ctx, cfg)
}

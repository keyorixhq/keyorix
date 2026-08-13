package core

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// Anomaly config knob ceilings (#G44) — without an upper bound, a caller-supplied
// value drives real per-scan work: LookbackDays widens the audit_events window
// scanned every detection tick, and MLNumTrees/MLSampleSize scale the isolation-
// forest training cost directly, so an unbounded value is a resource-exhaustion
// vector each time the detector runs.
const (
	maxAnomalyLookbackDays  = 365
	maxAnomalyQuarantineHrs = 24 * 90 // 90 days
	maxAnomalyMLNumTrees    = 1000
	maxAnomalyMLSampleSize  = 100000
)

// validateAnomalyConfig bounds the knobs that drive per-scan detector cost.
func validateAnomalyConfig(cfg *models.AnomalyConfigRecord) error {
	if cfg.LookbackDays > maxAnomalyLookbackDays {
		return fmt.Errorf("lookback_days exceeds the maximum of %d", maxAnomalyLookbackDays)
	}
	if cfg.QuarantineHours > maxAnomalyQuarantineHrs {
		return fmt.Errorf("quarantine_hours exceeds the maximum of %d", maxAnomalyQuarantineHrs)
	}
	if cfg.MLNumTrees > maxAnomalyMLNumTrees {
		return fmt.Errorf("ml_num_trees exceeds the maximum of %d", maxAnomalyMLNumTrees)
	}
	if cfg.MLSampleSize > maxAnomalyMLSampleSize {
		return fmt.Errorf("ml_sample_size exceeds the maximum of %d", maxAnomalyMLSampleSize)
	}
	return nil
}

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
	// Volume spike floor and cumulative rate rule (ANOMALY-06).
	if cfg.VolumeMinCount > 0 {
		detector.SetVolumeMinCount(cfg.VolumeMinCount)
	}
	if cfg.CumulativeRateFloor > 0 {
		detector.SetCumulativeRateFloor(cfg.CumulativeRateFloor)
	}
	if cfg.CumulativeRateMax > 0 {
		detector.SetCumulativeRateMax(cfg.CumulativeRateMax)
	}
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
	if err := validateAnomalyConfig(cfg); err != nil {
		return err
	}
	cfg.UpdatedBy = updatedBy
	cfg.UpdatedAt = time.Now()
	return c.storage.SaveAnomalyConfig(ctx, cfg)
}

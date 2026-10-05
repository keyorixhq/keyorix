// local_secret_schedule.go — SecretAccessSchedule persistence (temporal access policies).
// Each row constrains read access to a secret within a day-of-week + hour window.
// For the remote equivalent see remote_secret_schedule.go.
package store

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// GetSecretAccessSchedule returns the schedule for secretNodeID, or nil, nil
// if none exists. Served from the read-path metadata cache (PERF-3,
// docs/specs/read-path-caching.md) under its own generation signal
// (secret_access_schedules.cache_generation) — independent of
// GetSecret/GetLatestSecretVersion's secret_nodes-based one, since a
// schedule write touches a different table. See secret_metadata_cache.go.
func (ls *LocalStorage) GetSecretAccessSchedule(ctx context.Context, secretNodeID uint) (*models.SecretAccessSchedule, error) {
	if schedule, hit := ls.getCachedSchedule(ctx, secretNodeID); hit {
		if schedule == nil {
			return nil, nil
		}
		cp := *schedule
		return &cp, nil
	}
	var row models.SecretAccessSchedule
	err := ls.db.WithContext(ctx).Where("secret_node_id = ?", secretNodeID).First(&row).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			ls.secretMetaCache.evictSchedule(secretNodeID)
			return nil, nil
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	liveGen, found, genErr := liveScheduleGeneration(ctx, ls.db, secretNodeID)
	if genErr == nil && found {
		cp := row
		ls.secretMetaCache.setSchedule(secretNodeID, secretScheduleCacheEntry{generation: liveGen, hasSchedule: true, schedule: &cp})
	}
	return &row, nil
}

// getCachedSchedule returns (schedule, true) on a confirmed-current hit.
// Only a secret that HAS a schedule row is ever cached — "no schedule
// exists" has no generation column to validate a cached negative against
// (there's no row to read one from), so that case is deliberately never
// cached and always falls through to a live read; this is a documented
// perf-only limitation, not a correctness gap. Returns (nil, false) on any
// miss, including a generation-check error (fail closed: never trust the
// cache over a check that itself failed) or the row having been deleted
// since this entry was cached.
func (ls *LocalStorage) getCachedSchedule(ctx context.Context, secretNodeID uint) (*models.SecretAccessSchedule, bool) {
	cached, ok := ls.secretMetaCache.getSchedule(secretNodeID)
	if !ok || !cached.hasSchedule {
		return nil, false
	}
	liveGen, found, err := liveScheduleGeneration(ctx, ls.db, secretNodeID)
	if err != nil || !found {
		return nil, false
	}
	if !liveGen.Equal(cached.generation) {
		return nil, false
	}
	return cached.schedule, true
}

// SetSecretAccessSchedule upserts the schedule for schedule.SecretNodeID.
func (ls *LocalStorage) SetSecretAccessSchedule(ctx context.Context, schedule *models.SecretAccessSchedule) error {
	result := ls.db.WithContext(ctx).
		Where(models.SecretAccessSchedule{SecretNodeID: schedule.SecretNodeID}).
		Assign(models.SecretAccessSchedule{
			AllowedDays: schedule.AllowedDays,
			StartHour:   schedule.StartHour,
			EndHour:     schedule.EndHour,
			Timezone:    schedule.Timezone,
		}).
		FirstOrCreate(schedule)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	// If the row already existed (RowsAffected == 0 from FirstOrCreate), persist the Assign'd fields.
	if result.RowsAffected == 0 {
		if err := ls.db.WithContext(ctx).Save(schedule).Error; err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
	}
	return nil
}

// DeleteSecretAccessSchedule removes the schedule for secretNodeID.
// Returns nil if no schedule exists (idempotent).
func (ls *LocalStorage) DeleteSecretAccessSchedule(ctx context.Context, secretNodeID uint) error {
	result := ls.db.WithContext(ctx).
		Where("secret_node_id = ?", secretNodeID).
		Delete(&models.SecretAccessSchedule{})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return nil
}

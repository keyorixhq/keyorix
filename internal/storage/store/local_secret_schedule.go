// local_secret_schedule.go — SecretAccessSchedule persistence (temporal access policies).
// Each row constrains read access to a secret within a day-of-week + hour window.
// For the remote equivalent see remote_secret_schedule.go.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// errScheduleAbsent is GetSecretAccessSchedule's internal "no schedule row"
// signal. It is an error rather than a nil value so the read-path helper DROPS
// the cache entry instead of caching a negative: "no schedule exists" has no
// updated_at to stamp a negative with, so there is nothing to validate it
// against. That case therefore always falls through to a live read — a
// documented perf-only limitation, not a correctness gap. Never returned to a
// caller; GetSecretAccessSchedule maps it back to (nil, nil).
var errScheduleAbsent = errors.New("secret access schedule: no row")

// GetSecretAccessSchedule returns the schedule for secretNodeID, or nil, nil
// if none exists.
//
// SAME-ROW case (read_path_cache.go's cachedReadSameRow): the generation is the
// schedule row's own (updated_at, allowed_days, start_hour, end_hour,
// timezone), returned by the SAME query as the row, so there is no window
// between reading the data and reading the stamp. The policy columns are in the
// stamp, not just updated_at, so two schedule writes landing in one stored
// timestamp tick cannot tie unless they are the same policy — an access
// schedule is a read GATE, so a stale one keeps a closed window open. See
// scheduleGeneration in secret_metadata_cache.go.
//
// There is no `cache_generation` column on this table; an earlier version of
// this comment said there was, which was wrong.
func (ls *LocalStorage) GetSecretAccessSchedule(ctx context.Context, secretNodeID uint) (*models.SecretAccessSchedule, error) {
	schedule, err := cachedReadSameRow(ctx, ls, ls.secretMetaCache.schedules, secretNodeID,
		ls.scheduleGenerationFor(secretNodeID),
		func(ctx context.Context) (*models.SecretAccessSchedule, scheduleGeneration, error) {
			var row models.SecretAccessSchedule
			if err := ls.db.WithContext(ctx).Where("secret_node_id = ?", secretNodeID).First(&row).Error; err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return nil, scheduleGeneration{}, errScheduleAbsent
				}
				return nil, scheduleGeneration{}, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
			}
			cached := row
			return &cached, scheduleGenerationOf(&row), nil
		})
	if errors.Is(err, errScheduleAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cp := *schedule
	return &cp, nil
}

// scheduleGenerationFor binds the schedule generation read to one secret, in
// the shape read_path_cache.go expects.
func (ls *LocalStorage) scheduleGenerationFor(secretNodeID uint) genGeneration[scheduleGeneration] {
	return func(ctx context.Context) (scheduleGeneration, bool, error) {
		return liveScheduleGeneration(ctx, ls.db, secretNodeID)
	}
}

// getCachedSchedule returns (schedule, true) on a confirmed-current hit, or
// (nil, false) on any miss — a generation-check error (fail closed), the row
// having been deleted since the entry was cached, or a transaction-scoped
// store (cacheEnabled, checked inside the helper). Read-only probe, through
// the helper's own hit check so it cannot diverge.
func (ls *LocalStorage) getCachedSchedule(ctx context.Context, secretNodeID uint) (*models.SecretAccessSchedule, bool) {
	return cachedHit(ctx, ls, ls.secretMetaCache.schedules, secretNodeID, ls.scheduleGenerationFor(secretNodeID))
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

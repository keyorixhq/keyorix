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
	"gorm.io/gorm/clause"
)

// GetSecretAccessSchedule returns the schedule for secretNodeID, or nil, nil
// if none exists. Served from the read-path metadata cache (PERF-3,
// docs/specs/read-path-caching.md) under its own generation signal — the
// schedule row's own (updated_at, allowed_days, start_hour, end_hour,
// timezone), read in the SAME query as the row. Independent of
// GetSecret/GetLatestSecretVersion's signals, since a schedule write touches a
// different table. See secret_metadata_cache.go.
//
// There is no `cache_generation` column on this table; an earlier version of
// this comment said there was, which was wrong.
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
	// The generation is this row's own, read in the same query as the row
	// (coordinator review of #2764): a separate later generation read could see
	// a newer schedule and cache this older row under it. Never published from
	// inside a transaction — the row would be UNCOMMITTED (see cacheEnabled's
	// doc comment on LocalStorage).
	if ls.cacheEnabled {
		cp := row
		ls.secretMetaCache.setSchedule(secretNodeID, secretScheduleCacheEntry{
			generation: scheduleGenerationOf(&row), schedule: &cp,
		})
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
// cache over a check that itself failed), the row having been deleted since
// this entry was cached, and a transaction-scoped store (cacheEnabled).
func (ls *LocalStorage) getCachedSchedule(ctx context.Context, secretNodeID uint) (*models.SecretAccessSchedule, bool) {
	if !ls.cacheEnabled {
		return nil, false
	}
	cached, ok := ls.secretMetaCache.getSchedule(secretNodeID)
	if !ok {
		return nil, false
	}
	liveGen, found, err := liveScheduleGeneration(ctx, ls.db, secretNodeID)
	if err != nil || !found || liveGen != cached.generation {
		return nil, false
	}
	return cached.schedule, true
}

// SetSecretAccessSchedule upserts the schedule for schedule.SecretNodeID and fills
// schedule from the row written.
//
// Each attempt is one column-scoped UPDATE of the four window columns WHERE
// secret_node_id = ?, so it writes only while a row exists, and when it matches none an
// INSERT ... ON CONFLICT (secret_node_id) DO NOTHING of a new row. A conflict means
// another writer created the row in between; the next attempt updates that row. It
// replaces FirstOrCreate + Assign followed by a full-row Save (STORE-LOCKS-NOV-1): a
// schedule deleted between FirstOrCreate's read and its UPDATE was re-inserted by the
// Save under its old id and created_at, one deleted and re-created in that window made
// the Save fail on the secret_node_id unique index, and the struct-form Assign dropped
// zero values, so moving an existing window's start to hour 0 was not written.
func (ls *LocalStorage) SetSecretAccessSchedule(ctx context.Context, schedule *models.SecretAccessSchedule) error {
	db := ls.db.WithContext(ctx)
	window := map[string]any{
		"allowed_days": schedule.AllowedDays,
		"start_hour":   schedule.StartHour,
		"end_hour":     schedule.EndHour,
		"timezone":     schedule.Timezone,
	}
	for range 3 {
		updated := db.Model(&models.SecretAccessSchedule{}).
			Where("secret_node_id = ?", schedule.SecretNodeID).Updates(window)
		if updated.Error != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), updated.Error)
		}
		if updated.RowsAffected > 0 {
			var row models.SecretAccessSchedule
			err := db.Where("secret_node_id = ?", schedule.SecretNodeID).First(&row).Error
			switch {
			case err == nil:
				*schedule = row
			case !errors.Is(err, gorm.ErrRecordNotFound):
				return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
			}
			// Not found: a delete landed after this write; the caller keeps its values.
			return nil
		}
		row := models.SecretAccessSchedule{
			SecretNodeID: schedule.SecretNodeID,
			AllowedDays:  schedule.AllowedDays,
			StartHour:    schedule.StartHour,
			EndHour:      schedule.EndHour,
			Timezone:     schedule.Timezone,
		}
		created := db.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "secret_node_id"}}, DoNothing: true}).
			Create(&row)
		if created.Error != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), created.Error)
		}
		if created.RowsAffected > 0 {
			*schedule = row
			return nil
		}
	}
	return fmt.Errorf("%s: the schedule of secret %d kept changing concurrently", i18n.T("ErrorStorageFailed", nil), schedule.SecretNodeID)
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

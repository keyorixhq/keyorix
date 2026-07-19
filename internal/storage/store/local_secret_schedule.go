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

// GetSecretAccessSchedule returns the schedule for secretNodeID, or nil, nil if none exists.
func (ls *LocalStorage) GetSecretAccessSchedule(ctx context.Context, secretNodeID uint) (*models.SecretAccessSchedule, error) {
	var row models.SecretAccessSchedule
	err := ls.db.WithContext(ctx).Where("secret_node_id = ?", secretNodeID).First(&row).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &row, nil
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

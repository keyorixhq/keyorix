// local_mfa_stepup_grant.go — MFAStepUpGrant persistence for LocalStorage.
// Each VerifyMFAStepUp call creates a new grant row; queries return the most
// recent non-expired one. Expired rows are kept for audit purposes.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

func (ls *LocalStorage) CreateMFAStepUpGrant(ctx context.Context, grant *models.MFAStepUpGrant) error {
	return ls.db.WithContext(ctx).Create(grant).Error
}

func (ls *LocalStorage) GetActiveMFAStepUpGrant(ctx context.Context, userID uint, now time.Time) (*models.MFAStepUpGrant, error) {
	var g models.MFAStepUpGrant
	err := ls.db.WithContext(ctx).
		Where("user_id = ? AND expires_at > ?", userID, now.UTC()).
		Order("expires_at DESC").
		First(&g).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &g, nil
}

func (ls *LocalStorage) DeleteMFAStepUpGrantsFor(ctx context.Context, userID uint) error {
	return ls.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Delete(&models.MFAStepUpGrant{}).Error
}

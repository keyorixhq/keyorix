// local_mfa_reset.go — administrator MFA reset persistence (RECOVERY-MFA-RESET-1).
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) SetUserMFAEnrolmentRequired(ctx context.Context, userID uint, required bool) error {
	res := ls.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", userID).Update("mfa_enrolment_required", required)
	if res.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), storage.ErrUserNotFound)
	}
	return nil
}

func (ls *LocalStorage) CreateMFAResetRequest(ctx context.Context, r *models.MFAResetRequest) (*models.MFAResetRequest, error) {
	if err := ls.db.WithContext(ctx).Create(r).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return r, nil
}

func (ls *LocalStorage) GetMFAResetRequest(ctx context.Context, id uint) (*models.MFAResetRequest, error) {
	var r models.MFAResetRequest
	err := ls.db.WithContext(ctx).First(&r, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), storage.ErrMFAResetRequestNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &r, nil
}

func (ls *LocalStorage) ListMFAResetRequests(ctx context.Context, pendingOnly bool) ([]*models.MFAResetRequest, error) {
	var rows []*models.MFAResetRequest
	q := ls.db.WithContext(ctx).Order("id DESC")
	if pendingOnly {
		q = q.Where("status = ?", models.MFAResetStatusPending)
	}
	if err := q.Limit(maxUnboundedListRows).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) DecideMFAResetRequestIfPending(ctx context.Context, id uint, status string, decidedBy uint, now time.Time) (bool, error) {
	if status != models.MFAResetStatusApproved && status != models.MFAResetStatusCancelled {
		return false, fmt.Errorf("%s: invalid MFA reset decision %q", i18n.T("ErrorValidation", nil), status)
	}
	decidedAt := now.UTC()
	res := ls.db.WithContext(ctx).Model(&models.MFAResetRequest{}).
		Where("id = ? AND status = ? AND expires_at > ?", id, models.MFAResetStatusPending, decidedAt).
		Updates(map[string]any{"status": status, "decided_by": decidedBy, "decided_at": decidedAt})
	if res.Error != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	return res.RowsAffected == 1, nil
}

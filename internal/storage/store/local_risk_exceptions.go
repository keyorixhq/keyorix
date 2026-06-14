// local_risk_exceptions.go — risk-exception persistence (ISO 27001 A.5.8 risk
// treatment). For the remote equivalent see remote_risk_exceptions.go (server-side).
package store

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) CreateRiskException(ctx context.Context, e *models.RiskException) (*models.RiskException, error) {
	if err := ls.db.WithContext(ctx).Create(e).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return e, nil
}

// ListRiskExceptions returns risk exceptions newest-first. When activeOnly is set,
// revoked rows are excluded (expiry is computed in core, not at the storage layer).
func (ls *LocalStorage) ListRiskExceptions(ctx context.Context, activeOnly bool) ([]*models.RiskException, error) {
	var rows []*models.RiskException
	q := ls.db.WithContext(ctx).Order("id DESC")
	if activeOnly {
		q = q.Where("revoked = ?", false)
	}
	if err := q.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) GetRiskException(ctx context.Context, id uint) (*models.RiskException, error) {
	var e models.RiskException
	err := ls.db.WithContext(ctx).First(&e, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &e, nil
}

func (ls *LocalStorage) UpdateRiskException(ctx context.Context, e *models.RiskException) error {
	if err := ls.db.WithContext(ctx).Save(e).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

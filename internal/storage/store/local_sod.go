// local_sod.go — separation-of-duties policy persistence (ISO 27001 A.5.3 / SOX).
// For the remote equivalent see remote_sod.go (server-side only).
package store

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) CreateSoDPolicy(ctx context.Context, p *models.SoDPolicy) (*models.SoDPolicy, error) {
	if err := ls.db.WithContext(ctx).Create(p).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return p, nil
}

func (ls *LocalStorage) GetSoDPolicy(ctx context.Context, id uint) (*models.SoDPolicy, error) {
	var p models.SoDPolicy
	if err := ls.db.WithContext(ctx).First(&p, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &p, nil
}

func (ls *LocalStorage) ListSoDPolicies(ctx context.Context) ([]*models.SoDPolicy, error) {
	var rows []*models.SoDPolicy
	if err := ls.db.WithContext(ctx).Order("id ASC").Limit(maxUnboundedListRows).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) DeleteSoDPolicy(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Delete(&models.SoDPolicy{}, id)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}

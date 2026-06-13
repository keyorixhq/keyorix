// local_break_glass.go — break-glass emergency-access activation persistence
// (NIS2/DORA incident response). For the remote equivalent see remote_break_glass.go.
package store

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) CreateBreakGlassActivation(ctx context.Context, a *models.BreakGlassActivation) (*models.BreakGlassActivation, error) {
	if err := ls.db.WithContext(ctx).Create(a).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return a, nil
}

func (ls *LocalStorage) GetBreakGlassActivation(ctx context.Context, id uint) (*models.BreakGlassActivation, error) {
	var a models.BreakGlassActivation
	if err := ls.db.WithContext(ctx).First(&a, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &a, nil
}

func (ls *LocalStorage) ListBreakGlassActivations(ctx context.Context, projectID uint) ([]*models.BreakGlassActivation, error) {
	var rows []*models.BreakGlassActivation
	err := ls.db.WithContext(ctx).
		Where("project_id = ?", projectID).
		Order("created_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) UpdateBreakGlassActivation(ctx context.Context, a *models.BreakGlassActivation) error {
	if err := ls.db.WithContext(ctx).Save(a).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

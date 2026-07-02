// local_break_glass.go — break-glass emergency-access activation persistence
// (NIS2/DORA incident response). For the remote equivalent see remote_break_glass.go.
package store

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm/clause"
)

// CreateBreakGlassActivation persists a new activation. DoNothing on conflict so a
// racing duplicate active activation for the same (project_id, user_id) — the
// partial unique index enforced by ensureBreakGlassActiveIndex — is a clean,
// driver-agnostic (SQLite + Postgres) rejection rather than a raw unique-violation
// error: RowsAffected==0 means the insert was rejected, reported as
// storage.ErrBreakGlassAlreadyActive so the core layer can surface the same friendly
// message a losing racer gets from its own pre-check.
func (ls *LocalStorage) CreateBreakGlassActivation(ctx context.Context, a *models.BreakGlassActivation) (*models.BreakGlassActivation, error) {
	res := ls.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(a)
	if res.Error != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	if res.RowsAffected == 0 {
		return nil, storage.ErrBreakGlassAlreadyActive
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

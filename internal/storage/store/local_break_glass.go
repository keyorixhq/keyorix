// local_break_glass.go — break-glass emergency-access activation persistence
// (NIS2/DORA incident response). For the remote equivalent see remote_break_glass.go.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// breakGlassActiveState / breakGlassRevokedState mirror core.BreakGlassActive /
// core.BreakGlassRevoked. Duplicated here (rather than imported) because this
// package is imported BY internal/core — importing core back would cycle.
const (
	breakGlassActiveState  = "active"
	breakGlassRevokedState = "revoked"
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

// RevokeBreakGlassActivation conditionally transitions activation id from active to
// revoked in a single UPDATE ... WHERE state = 'active' — not a read-then-write —
// so a concurrent revoke of the same activation cannot silently overwrite this
// one's RevokedBy/RevokedAt. Returns storage.ErrBreakGlassNotActive (wrapped) if
// the row was not active (already revoked, or absent).
func (ls *LocalStorage) RevokeBreakGlassActivation(ctx context.Context, id, revokedBy uint, revokedAt time.Time) error {
	result := ls.db.WithContext(ctx).Model(&models.BreakGlassActivation{}).
		Where("id = ? AND state = ?", id, breakGlassActiveState).
		Updates(map[string]interface{}{
			"state":      breakGlassRevokedState,
			"revoked_by": revokedBy,
			"revoked_at": revokedAt,
		})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), storage.ErrBreakGlassNotActive)
	}
	return nil
}

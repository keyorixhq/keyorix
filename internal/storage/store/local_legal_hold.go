// local_legal_hold.go — legal-hold persistence (ISO 27001 A.5.34 / eDiscovery).
// For the remote equivalent see remote_legal_hold.go (server-side only).
package store

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) CreateLegalHold(ctx context.Context, h *models.LegalHold) (*models.LegalHold, error) {
	if err := ls.db.WithContext(ctx).Create(h).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return h, nil
}

// GetActiveLegalHold returns the current un-released hold, or (nil, nil) when none
// is active.
func (ls *LocalStorage) GetActiveLegalHold(ctx context.Context) (*models.LegalHold, error) {
	var h models.LegalHold
	err := ls.db.WithContext(ctx).Where("released = ?", false).Order("id DESC").First(&h).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &h, nil
}

func (ls *LocalStorage) UpdateLegalHold(ctx context.Context, h *models.LegalHold) error {
	if err := ls.db.WithContext(ctx).Save(h).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

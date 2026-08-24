// local_sod.go — separation-of-duties policy persistence (ISO 27001 A.5.3 / SOX).
// For the remote equivalent see remote_sod.go (server-side only).
package store

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) CreateSoDPolicy(ctx context.Context, p *models.SoDPolicy) (*models.SoDPolicy, error) {
	if err := ls.db.WithContext(ctx).Create(p).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return p, nil
}

// GetSoDPolicy used to wrap EVERY error from First (not just a genuine
// gorm.ErrRecordNotFound) with the "not found" i18n string -- surfaced by
// #1529's DeleteSoDPolicy fix, which now reads the policy before deleting it
// (to check creator-or-admin authority): a real connection failure ("database
// is closed") got mislabeled as "not found" and the proxy handler's
// isNotFoundErr string match (checking for "not found" in the error text) then
// reported 404 instead of 500 for a genuine storage outage. Matches the
// established gorm.ErrRecordNotFound-vs-everything-else pattern this package
// already uses elsewhere (e.g. local_alert_escalation.go's GetAlertEscalationPolicy).
func (ls *LocalStorage) GetSoDPolicy(ctx context.Context, id uint) (*models.SoDPolicy, error) {
	var p models.SoDPolicy
	err := ls.db.WithContext(ctx).First(&p, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
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

// local_bulk_access.go — LocalStorage implementations for rejection-reason
// templates and the multi-ID access-request lookup used by bulk approve/reject.
package store

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ── RejectionReasonTemplate ───────────────────────────────────────────────────

func (ls *LocalStorage) CreateRejectionReasonTemplate(ctx context.Context, t *models.RejectionReasonTemplate) error {
	if err := ls.db.WithContext(ctx).Create(t).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

func (ls *LocalStorage) ListRejectionReasonTemplates(ctx context.Context) ([]models.RejectionReasonTemplate, error) {
	var rows []models.RejectionReasonTemplate
	if err := ls.db.WithContext(ctx).Order("id ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) DeleteRejectionReasonTemplate(ctx context.Context, id uint) error {
	res := ls.db.WithContext(ctx).Delete(&models.RejectionReasonTemplate{}, id)
	if res.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}

// ── Bulk access-request lookup ────────────────────────────────────────────────

// ListAccessRequestsByIDs returns the access requests whose primary keys are in
// ids. The returned slice may be shorter than ids if some IDs do not exist.
func (ls *LocalStorage) ListAccessRequestsByIDs(ctx context.Context, ids []uint) ([]*models.AccessRequest, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var rows []*models.AccessRequest
	if err := ls.db.WithContext(ctx).Where("id IN ?", ids).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

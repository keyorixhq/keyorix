// local_access_review_campaigns.go — access-review campaign + item persistence
// (ISO 27001 A.5.18). For the remote (HTTP) equivalent see
// remote_access_review_campaigns.go (server-side only — stubs there).
package store

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// --- Campaigns ---

func (ls *LocalStorage) CreateAccessReviewCampaign(ctx context.Context, c *models.AccessReviewCampaign) (*models.AccessReviewCampaign, error) {
	if err := ls.db.WithContext(ctx).Create(c).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return c, nil
}

func (ls *LocalStorage) GetAccessReviewCampaign(ctx context.Context, id uint) (*models.AccessReviewCampaign, error) {
	var c models.AccessReviewCampaign
	if err := ls.db.WithContext(ctx).First(&c, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &c, nil
}

func (ls *LocalStorage) ListAccessReviewCampaigns(ctx context.Context, projectID uint) ([]*models.AccessReviewCampaign, error) {
	var rows []*models.AccessReviewCampaign
	err := ls.db.WithContext(ctx).
		Where("project_id = ?", projectID).
		Order("created_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) UpdateAccessReviewCampaign(ctx context.Context, c *models.AccessReviewCampaign) error {
	if err := ls.db.WithContext(ctx).Save(c).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// --- Items ---

func (ls *LocalStorage) CreateAccessReviewItems(ctx context.Context, items []*models.AccessReviewItem) error {
	if len(items) == 0 {
		return nil
	}
	if err := ls.db.WithContext(ctx).Create(items).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

func (ls *LocalStorage) ListAccessReviewItems(ctx context.Context, campaignID uint) ([]*models.AccessReviewItem, error) {
	var rows []*models.AccessReviewItem
	err := ls.db.WithContext(ctx).
		Where("campaign_id = ?", campaignID).
		Order("id ASC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) GetAccessReviewItem(ctx context.Context, id uint) (*models.AccessReviewItem, error) {
	var item models.AccessReviewItem
	if err := ls.db.WithContext(ctx).First(&item, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &item, nil
}

func (ls *LocalStorage) UpdateAccessReviewItem(ctx context.Context, item *models.AccessReviewItem) error {
	if err := ls.db.WithContext(ctx).Save(item).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

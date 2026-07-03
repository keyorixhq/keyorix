// remote_access_review_campaigns.go — access-review campaigns for RemoteStorage
// (ISO 27001 A.5.18). Processed server-side; stubs here. For the local (GORM)
// equivalent see local_access_review_campaigns.go.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateAccessReviewCampaign(_ context.Context, _ *models.AccessReviewCampaign) (*models.AccessReviewCampaign, error) {
	return nil, remoteUnsupported("CreateAccessReviewCampaign")
}

func (rs *RemoteStorage) GetAccessReviewCampaign(_ context.Context, _ uint) (*models.AccessReviewCampaign, error) {
	return nil, remoteUnsupported("GetAccessReviewCampaign")
}

func (rs *RemoteStorage) ListAccessReviewCampaigns(_ context.Context, _ uint) ([]*models.AccessReviewCampaign, error) {
	return nil, remoteUnsupported("ListAccessReviewCampaigns")
}

func (rs *RemoteStorage) UpdateAccessReviewCampaign(_ context.Context, _ *models.AccessReviewCampaign) (bool, error) {
	return false, remoteUnsupported("UpdateAccessReviewCampaign")
}

func (rs *RemoteStorage) CreateAccessReviewItems(_ context.Context, _ []*models.AccessReviewItem) error {
	return remoteUnsupported("CreateAccessReviewItems")
}

func (rs *RemoteStorage) ListAccessReviewItems(_ context.Context, _ uint) ([]*models.AccessReviewItem, error) {
	return nil, remoteUnsupported("ListAccessReviewItems")
}

func (rs *RemoteStorage) GetAccessReviewItem(_ context.Context, _ uint) (*models.AccessReviewItem, error) {
	return nil, remoteUnsupported("GetAccessReviewItem")
}

func (rs *RemoteStorage) UpdateAccessReviewItem(_ context.Context, _ *models.AccessReviewItem) (bool, error) {
	return false, remoteUnsupported("UpdateAccessReviewItem")
}

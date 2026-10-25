package storagetest

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) CreateAccessRequestApproval(ctx context.Context, a *models.AccessRequestApproval) error {
	if hk := hs.h.CreateAccessRequestApproval; hk != nil {
		return hk(hs.Storage, ctx, a)
	}
	return hs.Storage.CreateAccessRequestApproval(ctx, a)
}

func (hs *HookStore) CreateAccessReviewItems(ctx context.Context, items []*models.AccessReviewItem) error {
	if hk := hs.h.CreateAccessReviewItems; hk != nil {
		return hk(hs.Storage, ctx, items)
	}
	return hs.Storage.CreateAccessReviewItems(ctx, items)
}

func (hs *HookStore) ListSoDPolicies(ctx context.Context) ([]*models.SoDPolicy, error) {
	if hk := hs.h.ListSoDPolicies; hk != nil {
		return hk(hs.Storage, ctx)
	}
	return hs.Storage.ListSoDPolicies(ctx)
}

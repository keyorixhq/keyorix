package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) GetMFAResetRequest(ctx context.Context, id uint) (*models.MFAResetRequest, error) {
	if hk := hs.h.GetMFAResetRequest; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.GetMFAResetRequest(ctx, id)
}

func (hs *HookStore) ListMFAResetRequests(ctx context.Context, pendingOnly bool) ([]*models.MFAResetRequest, error) {
	if hk := hs.h.ListMFAResetRequests; hk != nil {
		return hk(hs.Storage, ctx, pendingOnly)
	}
	return hs.Storage.ListMFAResetRequests(ctx, pendingOnly)
}

func (hs *HookStore) DecideMFAResetRequestIfPending(ctx context.Context, id uint, status string, decidedBy uint, now time.Time) (bool, error) {
	if hk := hs.h.DecideMFAResetRequestIfPending; hk != nil {
		return hk(hs.Storage, ctx, id, status, decidedBy, now)
	}
	return hs.Storage.DecideMFAResetRequestIfPending(ctx, id, status, decidedBy, now)
}

package storagetest

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) CreateNotification(ctx context.Context, n *models.Notification) (*models.Notification, error) {
	if hk := hs.h.CreateNotification; hk != nil {
		return hk(hs.Storage, ctx, n)
	}
	return hs.Storage.CreateNotification(ctx, n)
}

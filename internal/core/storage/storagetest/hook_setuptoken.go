package storagetest

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) CreateSetupToken(ctx context.Context, t *models.SetupToken) (*models.SetupToken, error) {
	if hk := hs.h.CreateSetupToken; hk != nil {
		return hk(hs.Storage, ctx, t)
	}
	return hs.Storage.CreateSetupToken(ctx, t)
}

package storagetest

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) ListPersonalAccessTokensByUser(ctx context.Context, userID uint) ([]*models.PersonalAccessToken, error) {
	if hk := hs.h.ListPersonalAccessTokensByUser; hk != nil {
		return hk(hs.Storage, ctx, userID)
	}
	return hs.Storage.ListPersonalAccessTokensByUser(ctx, userID)
}

func (hs *HookStore) RevokeAllPersonalAccessTokensForUser(ctx context.Context, userID uint) ([]string, error) {
	if hk := hs.h.RevokeAllPersonalAccessTokensForUser; hk != nil {
		return hk(hs.Storage, ctx, userID)
	}
	return hs.Storage.RevokeAllPersonalAccessTokensForUser(ctx, userID)
}

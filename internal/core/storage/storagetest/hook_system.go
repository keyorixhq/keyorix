package storagetest

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

func (hs *HookStore) GetStats(ctx context.Context) (*storage.StorageStats, error) {
	if hk := hs.h.GetStats; hk != nil {
		return hk(hs.Storage, ctx)
	}
	return hs.Storage.GetStats(ctx)
}

func (hs *HookStore) SetSystemMetadata(ctx context.Context, key string, value string) error {
	if hk := hs.h.SetSystemMetadata; hk != nil {
		return hk(hs.Storage, ctx, key, value)
	}
	return hs.Storage.SetSystemMetadata(ctx, key, value)
}

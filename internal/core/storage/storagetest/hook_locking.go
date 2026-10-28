package storagetest

import (
	"context"
)

func (hs *HookStore) WithNamedLock(ctx context.Context, lockKey string, fn func(ctx context.Context) error) error {
	if hk := hs.h.WithNamedLock; hk != nil {
		return hk(hs.Storage, ctx, lockKey, fn)
	}
	return hs.Storage.WithNamedLock(ctx, lockKey, fn)
}

func (hs *HookStore) LockNamedKeyInTx(ctx context.Context, lockKey string) error {
	if hk := hs.h.LockNamedKeyInTx; hk != nil {
		return hk(hs.Storage, ctx, lockKey)
	}
	return hs.Storage.LockNamedKeyInTx(ctx, lockKey)
}

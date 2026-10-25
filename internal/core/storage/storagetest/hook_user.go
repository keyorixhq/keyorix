package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) GetUser(ctx context.Context, id uint) (*models.User, error) {
	if hk := hs.h.GetUser; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.GetUser(ctx, id)
}

func (hs *HookStore) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	if hk := hs.h.GetUserByUsername; hk != nil {
		return hk(hs.Storage, ctx, username)
	}
	return hs.Storage.GetUserByUsername(ctx, username)
}

func (hs *HookStore) ListUsers(ctx context.Context, filter *storage.UserFilter) ([]*models.User, int64, error) {
	if hk := hs.h.ListUsers; hk != nil {
		return hk(hs.Storage, ctx, filter)
	}
	return hs.Storage.ListUsers(ctx, filter)
}

func (hs *HookStore) LockUserForUpdate(ctx context.Context, id uint) (*models.User, error) {
	if hk := hs.h.LockUserForUpdate; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.LockUserForUpdate(ctx, id)
}

func (hs *HookStore) SetAccountState(ctx context.Context, id uint, state string, updatedAt time.Time) error {
	if hk := hs.h.SetAccountState; hk != nil {
		return hk(hs.Storage, ctx, id, state, updatedAt)
	}
	return hs.Storage.SetAccountState(ctx, id, state, updatedAt)
}

func (hs *HookStore) UpdateLastLogin(ctx context.Context, userID uint, loginAt time.Time) error {
	if hk := hs.h.UpdateLastLogin; hk != nil {
		return hk(hs.Storage, ctx, userID, loginAt)
	}
	return hs.Storage.UpdateLastLogin(ctx, userID, loginAt)
}

func (hs *HookStore) UpdateLoginLockoutState(ctx context.Context, id uint, attempts int, lastFailedAt *time.Time, lockedUntil *time.Time, lockoutCount int) error {
	if hk := hs.h.UpdateLoginLockoutState; hk != nil {
		return hk(hs.Storage, ctx, id, attempts, lastFailedAt, lockedUntil, lockoutCount)
	}
	return hs.Storage.UpdateLoginLockoutState(ctx, id, attempts, lastFailedAt, lockedUntil, lockoutCount)
}

func (hs *HookStore) UpdateUser(ctx context.Context, user *models.User) (*models.User, error) {
	if hk := hs.h.UpdateUser; hk != nil {
		return hk(hs.Storage, ctx, user)
	}
	return hs.Storage.UpdateUser(ctx, user)
}

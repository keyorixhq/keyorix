package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) CountRecentLoginAttempts(ctx context.Context, ip string, since time.Time) (int64, error) {
	if hk := hs.h.CountRecentLoginAttempts; hk != nil {
		return hk(hs.Storage, ctx, ip, since)
	}
	return hs.Storage.CountRecentLoginAttempts(ctx, ip, since)
}

func (hs *HookStore) CreateSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	if hk := hs.h.CreateSession; hk != nil {
		return hk(hs.Storage, ctx, session)
	}
	return hs.Storage.CreateSession(ctx, session)
}

func (hs *HookStore) DeleteSessionsForUserExcept(ctx context.Context, userID uint, exceptID uint) error {
	if hk := hs.h.DeleteSessionsForUserExcept; hk != nil {
		return hk(hs.Storage, ctx, userID, exceptID)
	}
	return hs.Storage.DeleteSessionsForUserExcept(ctx, userID, exceptID)
}

func (hs *HookStore) EnforceSessionLimit(ctx context.Context, userID uint, keep int) error {
	if hk := hs.h.EnforceSessionLimit; hk != nil {
		return hk(hs.Storage, ctx, userID, keep)
	}
	return hs.Storage.EnforceSessionLimit(ctx, userID, keep)
}

func (hs *HookStore) GetSession(ctx context.Context, token string) (*models.Session, error) {
	if hk := hs.h.GetSession; hk != nil {
		return hk(hs.Storage, ctx, token)
	}
	return hs.Storage.GetSession(ctx, token)
}

func (hs *HookStore) GetSessionByID(ctx context.Context, id uint) (*models.Session, error) {
	if hk := hs.h.GetSessionByID; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.GetSessionByID(ctx, id)
}

func (hs *HookStore) ListSessionTokenHashesForUser(ctx context.Context, userID uint) ([]string, error) {
	if hk := hs.h.ListSessionTokenHashesForUser; hk != nil {
		return hk(hs.Storage, ctx, userID)
	}
	return hs.Storage.ListSessionTokenHashesForUser(ctx, userID)
}

func (hs *HookStore) RecordLoginAttempt(ctx context.Context, ip string, at time.Time) error {
	if hk := hs.h.RecordLoginAttempt; hk != nil {
		return hk(hs.Storage, ctx, ip, at)
	}
	return hs.Storage.RecordLoginAttempt(ctx, ip, at)
}

func (hs *HookStore) ReleaseLoginAttempt(ctx context.Context, id uint) error {
	if hk := hs.h.ReleaseLoginAttempt; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.ReleaseLoginAttempt(ctx, id)
}

func (hs *HookStore) ReserveLoginAttempt(ctx context.Context, ip string, at time.Time, key string) (uint, error) {
	if hk := hs.h.ReserveLoginAttempt; hk != nil {
		return hk(hs.Storage, ctx, ip, at, key)
	}
	return hs.Storage.ReserveLoginAttempt(ctx, ip, at, key)
}

func (hs *HookStore) RotateSession(ctx context.Context, oldID uint, newSession *models.Session, now time.Time) (*models.Session, bool, error) {
	if hk := hs.h.RotateSession; hk != nil {
		return hk(hs.Storage, ctx, oldID, newSession, now)
	}
	return hs.Storage.RotateSession(ctx, oldID, newSession, now)
}

package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) ActivateMFASecret(ctx context.Context, userID uint, secretEnc []byte) (bool, error) {
	if hk := hs.h.ActivateMFASecret; hk != nil {
		return hk(hs.Storage, ctx, userID, secretEnc)
	}
	return hs.Storage.ActivateMFASecret(ctx, userID, secretEnc)
}

func (hs *HookStore) ConsumeMFAChallenge(ctx context.Context, tokenHash string, now time.Time) (*models.MFAChallenge, error) {
	if hk := hs.h.ConsumeMFAChallenge; hk != nil {
		return hk(hs.Storage, ctx, tokenHash, now)
	}
	return hs.Storage.ConsumeMFAChallenge(ctx, tokenHash, now)
}

func (hs *HookStore) ConsumeMFARecoveryCode(ctx context.Context, userID uint, codeHash string, now time.Time) (bool, error) {
	if hk := hs.h.ConsumeMFARecoveryCode; hk != nil {
		return hk(hs.Storage, ctx, userID, codeHash, now)
	}
	return hs.Storage.ConsumeMFARecoveryCode(ctx, userID, codeHash, now)
}

func (hs *HookStore) CreateMFARecoveryCodes(ctx context.Context, userID uint, codeHashes []string) error {
	if hk := hs.h.CreateMFARecoveryCodes; hk != nil {
		return hk(hs.Storage, ctx, userID, codeHashes)
	}
	return hs.Storage.CreateMFARecoveryCodes(ctx, userID, codeHashes)
}

func (hs *HookStore) CreateMFAStepUpGrant(ctx context.Context, grant *models.MFAStepUpGrant) error {
	if hk := hs.h.CreateMFAStepUpGrant; hk != nil {
		return hk(hs.Storage, ctx, grant)
	}
	return hs.Storage.CreateMFAStepUpGrant(ctx, grant)
}

func (hs *HookStore) DeleteMFAForUser(ctx context.Context, userID uint) error {
	if hk := hs.h.DeleteMFAForUser; hk != nil {
		return hk(hs.Storage, ctx, userID)
	}
	return hs.Storage.DeleteMFAForUser(ctx, userID)
}

func (hs *HookStore) DeleteMFARecoveryCodes(ctx context.Context, userID uint) error {
	if hk := hs.h.DeleteMFARecoveryCodes; hk != nil {
		return hk(hs.Storage, ctx, userID)
	}
	return hs.Storage.DeleteMFARecoveryCodes(ctx, userID)
}

func (hs *HookStore) GetMFASecret(ctx context.Context, userID uint) (*models.MFASecret, error) {
	if hk := hs.h.GetMFASecret; hk != nil {
		return hk(hs.Storage, ctx, userID)
	}
	return hs.Storage.GetMFASecret(ctx, userID)
}

func (hs *HookStore) MarkTOTPStepUsed(ctx context.Context, userID uint, step int64) (bool, error) {
	if hk := hs.h.MarkTOTPStepUsed; hk != nil {
		return hk(hs.Storage, ctx, userID, step)
	}
	return hs.Storage.MarkTOTPStepUsed(ctx, userID, step)
}

func (hs *HookStore) SetUserMFAEnabled(ctx context.Context, userID uint, enabled bool) error {
	if hk := hs.h.SetUserMFAEnabled; hk != nil {
		return hk(hs.Storage, ctx, userID, enabled)
	}
	return hs.Storage.SetUserMFAEnabled(ctx, userID, enabled)
}

package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) AdvanceWebAuthnCredentialCounter(ctx context.Context, credentialID []byte, userID uint, newBlob []byte, newSignCount uint32, lastUsedAt time.Time) (bool, error) {
	if hk := hs.h.AdvanceWebAuthnCredentialCounter; hk != nil {
		return hk(hs.Storage, ctx, credentialID, userID, newBlob, newSignCount, lastUsedAt)
	}
	return hs.Storage.AdvanceWebAuthnCredentialCounter(ctx, credentialID, userID, newBlob, newSignCount, lastUsedAt)
}

func (hs *HookStore) ConsumeWebAuthnSession(ctx context.Context, tokenHash string, now time.Time) (*models.WebAuthnSession, error) {
	if hk := hs.h.ConsumeWebAuthnSession; hk != nil {
		return hk(hs.Storage, ctx, tokenHash, now)
	}
	return hs.Storage.ConsumeWebAuthnSession(ctx, tokenHash, now)
}

func (hs *HookStore) CountWebAuthnCredentials(ctx context.Context, userID uint) (int64, error) {
	if hk := hs.h.CountWebAuthnCredentials; hk != nil {
		return hk(hs.Storage, ctx, userID)
	}
	return hs.Storage.CountWebAuthnCredentials(ctx, userID)
}

func (hs *HookStore) CreateWebAuthnCredential(ctx context.Context, c *models.WebAuthnCredential) error {
	if hk := hs.h.CreateWebAuthnCredential; hk != nil {
		return hk(hs.Storage, ctx, c)
	}
	return hs.Storage.CreateWebAuthnCredential(ctx, c)
}

func (hs *HookStore) CreateWebAuthnSession(ctx context.Context, s *models.WebAuthnSession) error {
	if hk := hs.h.CreateWebAuthnSession; hk != nil {
		return hk(hs.Storage, ctx, s)
	}
	return hs.Storage.CreateWebAuthnSession(ctx, s)
}

func (hs *HookStore) DeleteWebAuthnCredential(ctx context.Context, userID uint, id uint) error {
	if hk := hs.h.DeleteWebAuthnCredential; hk != nil {
		return hk(hs.Storage, ctx, userID, id)
	}
	return hs.Storage.DeleteWebAuthnCredential(ctx, userID, id)
}

func (hs *HookStore) DisableWebAuthnCredential(ctx context.Context, id uint) (bool, error) {
	if hk := hs.h.DisableWebAuthnCredential; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.DisableWebAuthnCredential(ctx, id)
}

func (hs *HookStore) GetWebAuthnCredentialByCredID(ctx context.Context, credentialID []byte, userID uint) (*models.WebAuthnCredential, error) {
	if hk := hs.h.GetWebAuthnCredentialByCredID; hk != nil {
		return hk(hs.Storage, ctx, credentialID, userID)
	}
	return hs.Storage.GetWebAuthnCredentialByCredID(ctx, credentialID, userID)
}

func (hs *HookStore) ListWebAuthnCredentials(ctx context.Context, userID uint) ([]*models.WebAuthnCredential, error) {
	if hk := hs.h.ListWebAuthnCredentials; hk != nil {
		return hk(hs.Storage, ctx, userID)
	}
	return hs.Storage.ListWebAuthnCredentials(ctx, userID)
}

func (hs *HookStore) SetUserWebAuthnEnabled(ctx context.Context, userID uint, enabled bool) error {
	if hk := hs.h.SetUserWebAuthnEnabled; hk != nil {
		return hk(hs.Storage, ctx, userID, enabled)
	}
	return hs.Storage.SetUserWebAuthnEnabled(ctx, userID, enabled)
}

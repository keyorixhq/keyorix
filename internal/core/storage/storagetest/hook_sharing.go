package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) CreateOrUpdateSecretACL(ctx context.Context, acl *models.SecretACL) error {
	if hk := hs.h.CreateOrUpdateSecretACL; hk != nil {
		return hk(hs.Storage, ctx, acl)
	}
	return hs.Storage.CreateOrUpdateSecretACL(ctx, acl)
}

func (hs *HookStore) DeleteSecretACL(ctx context.Context, id uint) error {
	if hk := hs.h.DeleteSecretACL; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.DeleteSecretACL(ctx, id)
}

func (hs *HookStore) DeleteSecretACLsByUserAndProject(ctx context.Context, userID uint, projectID uint) error {
	if hk := hs.h.DeleteSecretACLsByUserAndProject; hk != nil {
		return hk(hs.Storage, ctx, userID, projectID)
	}
	return hs.Storage.DeleteSecretACLsByUserAndProject(ctx, userID, projectID)
}

func (hs *HookStore) GetSecretACL(ctx context.Context, secretID uint, userID uint) (*models.SecretACL, error) {
	if hk := hs.h.GetSecretACL; hk != nil {
		return hk(hs.Storage, ctx, secretID, userID)
	}
	return hs.Storage.GetSecretACL(ctx, secretID, userID)
}

func (hs *HookStore) GetSecretAncestors(ctx context.Context, nodeID uint) ([]uint, error) {
	if hk := hs.h.GetSecretAncestors; hk != nil {
		return hk(hs.Storage, ctx, nodeID)
	}
	return hs.Storage.GetSecretAncestors(ctx, nodeID)
}

func (hs *HookStore) ListSecretACLs(ctx context.Context, secretID uint) ([]*models.SecretACL, error) {
	if hk := hs.h.ListSecretACLs; hk != nil {
		return hk(hs.Storage, ctx, secretID)
	}
	return hs.Storage.ListSecretACLs(ctx, secretID)
}

func (hs *HookStore) ListSharesByOwner(ctx context.Context, ownerID uint, now time.Time) ([]*models.ShareRecord, error) {
	if hk := hs.h.ListSharesByOwner; hk != nil {
		return hk(hs.Storage, ctx, ownerID, now)
	}
	return hs.Storage.ListSharesByOwner(ctx, ownerID, now)
}

func (hs *HookStore) ListSharesBySecret(ctx context.Context, secretID uint, now time.Time) ([]*models.ShareRecord, error) {
	if hk := hs.h.ListSharesBySecret; hk != nil {
		return hk(hs.Storage, ctx, secretID, now)
	}
	return hs.Storage.ListSharesBySecret(ctx, secretID, now)
}

func (hs *HookStore) ListSharesByUser(ctx context.Context, userID uint, now time.Time) ([]*models.ShareRecord, error) {
	if hk := hs.h.ListSharesByUser; hk != nil {
		return hk(hs.Storage, ctx, userID, now)
	}
	return hs.Storage.ListSharesByUser(ctx, userID, now)
}

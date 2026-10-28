package storagetest

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) CreateSecretDependencyExclusive(ctx context.Context, d *models.SecretDependency) (*models.SecretDependency, error) {
	if hk := hs.h.CreateSecretDependencyExclusive; hk != nil {
		return hk(hs.Storage, ctx, d)
	}
	return hs.Storage.CreateSecretDependencyExclusive(ctx, d)
}

func (hs *HookStore) CreateSecretVersion(ctx context.Context, version *models.SecretVersion) (*models.SecretVersion, error) {
	if hk := hs.h.CreateSecretVersion; hk != nil {
		return hk(hs.Storage, ctx, version)
	}
	return hs.Storage.CreateSecretVersion(ctx, version)
}

func (hs *HookStore) GetLatestSecretVersion(ctx context.Context, secretID uint) (*models.SecretVersion, error) {
	if hk := hs.h.GetLatestSecretVersion; hk != nil {
		return hk(hs.Storage, ctx, secretID)
	}
	return hs.Storage.GetLatestSecretVersion(ctx, secretID)
}

func (hs *HookStore) GetSecret(ctx context.Context, id uint) (*models.SecretNode, error) {
	if hk := hs.h.GetSecret; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.GetSecret(ctx, id)
}

func (hs *HookStore) GetSecretByName(ctx context.Context, name string, projectID uint, environmentID uint) (*models.SecretNode, error) {
	if hk := hs.h.GetSecretByName; hk != nil {
		return hk(hs.Storage, ctx, name, projectID, environmentID)
	}
	return hs.Storage.GetSecretByName(ctx, name, projectID, environmentID)
}

func (hs *HookStore) ListSecrets(ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
	if hk := hs.h.ListSecrets; hk != nil {
		return hk(hs.Storage, ctx, filter)
	}
	return hs.Storage.ListSecrets(ctx, filter)
}

func (hs *HookStore) SetSecretTags(ctx context.Context, secretID uint, tagNames []string) error {
	if hk := hs.h.SetSecretTags; hk != nil {
		return hk(hs.Storage, ctx, secretID, tagNames)
	}
	return hs.Storage.SetSecretTags(ctx, secretID, tagNames)
}

func (hs *HookStore) UpdateSecretFields(ctx context.Context, id uint, f storage.SecretFieldUpdate) (bool, error) {
	if hk := hs.h.UpdateSecretFields; hk != nil {
		return hk(hs.Storage, ctx, id, f)
	}
	return hs.Storage.UpdateSecretFields(ctx, id, f)
}

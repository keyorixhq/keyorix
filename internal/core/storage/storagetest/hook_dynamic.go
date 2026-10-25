package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) GetDynamicSecretConfig(ctx context.Context, id uint) (*models.DynamicSecretConfig, error) {
	if hk := hs.h.GetDynamicSecretConfig; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.GetDynamicSecretConfig(ctx, id)
}

func (hs *HookStore) ListDynamicSecretConfigs(ctx context.Context, projectID uint, environmentID uint) ([]*models.DynamicSecretConfig, error) {
	if hk := hs.h.ListDynamicSecretConfigs; hk != nil {
		return hk(hs.Storage, ctx, projectID, environmentID)
	}
	return hs.Storage.ListDynamicSecretConfigs(ctx, projectID, environmentID)
}

func (hs *HookStore) ListDynamicSecretLeases(ctx context.Context, configID uint) ([]*models.DynamicSecretLease, error) {
	if hk := hs.h.ListDynamicSecretLeases; hk != nil {
		return hk(hs.Storage, ctx, configID)
	}
	return hs.Storage.ListDynamicSecretLeases(ctx, configID)
}

func (hs *HookStore) RecordDynamicSecretLeaseRevocation(ctx context.Context, leaseID string, status string, revokeReason string, revokeError string, revokedAt *time.Time) (bool, error) {
	if hk := hs.h.RecordDynamicSecretLeaseRevocation; hk != nil {
		return hk(hs.Storage, ctx, leaseID, status, revokeReason, revokeError, revokedAt)
	}
	return hs.Storage.RecordDynamicSecretLeaseRevocation(ctx, leaseID, status, revokeReason, revokeError, revokedAt)
}

package storagetest

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) CreateRotationPolicy(ctx context.Context, p *models.RotationPolicy) error {
	if hk := hs.h.CreateRotationPolicy; hk != nil {
		return hk(hs.Storage, ctx, p)
	}
	return hs.Storage.CreateRotationPolicy(ctx, p)
}

func (hs *HookStore) DeleteRotationPolicy(ctx context.Context, id uint) error {
	if hk := hs.h.DeleteRotationPolicy; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.DeleteRotationPolicy(ctx, id)
}

func (hs *HookStore) ListRotationPolicies(ctx context.Context, projectID *uint, environmentID *uint) ([]*models.RotationPolicy, error) {
	if hk := hs.h.ListRotationPolicies; hk != nil {
		return hk(hs.Storage, ctx, projectID, environmentID)
	}
	return hs.Storage.ListRotationPolicies(ctx, projectID, environmentID)
}

func (hs *HookStore) UpdateRotationPolicyFields(ctx context.Context, id uint, f storage.RotationPolicyFieldUpdate, updatedAt time.Time) (bool, error) {
	if hk := hs.h.UpdateRotationPolicyFields; hk != nil {
		return hk(hs.Storage, ctx, id, f, updatedAt)
	}
	return hs.Storage.UpdateRotationPolicyFields(ctx, id, f, updatedAt)
}

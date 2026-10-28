package storagetest

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) GetMachineRoleIDsAt(ctx context.Context, machineID uint, scope storage.Scope) ([]uint, error) {
	if hk := hs.h.GetMachineRoleIDsAt; hk != nil {
		return hk(hs.Storage, ctx, machineID, scope)
	}
	return hs.Storage.GetMachineRoleIDsAt(ctx, machineID, scope)
}

func (hs *HookStore) GetMachineRoleScopes(ctx context.Context, machineID uint) ([]storage.Scope, error) {
	if hk := hs.h.GetMachineRoleScopes; hk != nil {
		return hk(hs.Storage, ctx, machineID)
	}
	return hs.Storage.GetMachineRoleScopes(ctx, machineID)
}

func (hs *HookStore) RevokeMachineIdentityCredential(ctx context.Context, projectID uint, credentialID uint) error {
	if hk := hs.h.RevokeMachineIdentityCredential; hk != nil {
		return hk(hs.Storage, ctx, projectID, credentialID)
	}
	return hs.Storage.RevokeMachineIdentityCredential(ctx, projectID, credentialID)
}

func (hs *HookStore) LockMachineIdentityForUpdate(ctx context.Context, id uint) (*models.MachineIdentity, error) {
	if hk := hs.h.LockMachineIdentityForUpdate; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.LockMachineIdentityForUpdate(ctx, id)
}

package storagetest

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) AddUserToGroup(ctx context.Context, userID uint, groupID uint, projectID uint) error {
	if hk := hs.h.AddUserToGroup; hk != nil {
		return hk(hs.Storage, ctx, userID, groupID, projectID)
	}
	return hs.Storage.AddUserToGroup(ctx, userID, groupID, projectID)
}

func (hs *HookStore) DeleteGroup(ctx context.Context, id uint) error {
	if hk := hs.h.DeleteGroup; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.DeleteGroup(ctx, id)
}

func (hs *HookStore) ListGroupMembers(ctx context.Context, groupID uint) ([]*models.User, error) {
	if hk := hs.h.ListGroupMembers; hk != nil {
		return hk(hs.Storage, ctx, groupID)
	}
	return hs.Storage.ListGroupMembers(ctx, groupID)
}

func (hs *HookStore) ListGroups(ctx context.Context) ([]*models.Group, error) {
	if hk := hs.h.ListGroups; hk != nil {
		return hk(hs.Storage, ctx)
	}
	return hs.Storage.ListGroups(ctx)
}

func (hs *HookStore) RemoveUserFromGroup(ctx context.Context, userID uint, groupID uint, projectID uint) error {
	if hk := hs.h.RemoveUserFromGroup; hk != nil {
		return hk(hs.Storage, ctx, userID, groupID, projectID)
	}
	return hs.Storage.RemoveUserFromGroup(ctx, userID, groupID, projectID)
}

func (hs *HookStore) RestoreGroup(ctx context.Context, id uint) error {
	if hk := hs.h.RestoreGroup; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.RestoreGroup(ctx, id)
}

package storagetest

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) CreateProjectMembership(ctx context.Context, m *models.ProjectMembership) (*models.ProjectMembership, error) {
	if hk := hs.h.CreateProjectMembership; hk != nil {
		return hk(hs.Storage, ctx, m)
	}
	return hs.Storage.CreateProjectMembership(ctx, m)
}

func (hs *HookStore) ListProjectMembers(ctx context.Context, projectID uint) ([]storage.ProjectMember, error) {
	if hk := hs.h.ListProjectMembers; hk != nil {
		return hk(hs.Storage, ctx, projectID)
	}
	return hs.Storage.ListProjectMembers(ctx, projectID)
}

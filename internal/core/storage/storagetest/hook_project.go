package storagetest

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (hs *HookStore) CreateEnvironment(ctx context.Context, env *models.Environment) (*models.Environment, error) {
	if hk := hs.h.CreateEnvironment; hk != nil {
		return hk(hs.Storage, ctx, env)
	}
	return hs.Storage.CreateEnvironment(ctx, env)
}

func (hs *HookStore) CreateProject(ctx context.Context, project *models.Project) (*models.Project, error) {
	if hk := hs.h.CreateProject; hk != nil {
		return hk(hs.Storage, ctx, project)
	}
	return hs.Storage.CreateProject(ctx, project)
}

func (hs *HookStore) DeleteProject(ctx context.Context, id uint) error {
	if hk := hs.h.DeleteProject; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.DeleteProject(ctx, id)
}

func (hs *HookStore) DeleteProjectIfEmpty(ctx context.Context, id uint) (int, error) {
	if hk := hs.h.DeleteProjectIfEmpty; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.DeleteProjectIfEmpty(ctx, id)
}

func (hs *HookStore) GetEnvironment(ctx context.Context, id uint) (*models.Environment, error) {
	if hk := hs.h.GetEnvironment; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.GetEnvironment(ctx, id)
}

func (hs *HookStore) ListProjects(ctx context.Context) ([]*models.Project, error) {
	if hk := hs.h.ListProjects; hk != nil {
		return hk(hs.Storage, ctx)
	}
	return hs.Storage.ListProjects(ctx)
}

func (hs *HookStore) SuspendMachineIdentitiesForDeletedProject(ctx context.Context, id uint) ([]*models.MachineIdentity, error) {
	if hk := hs.h.SuspendMachineIdentitiesForDeletedProject; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.SuspendMachineIdentitiesForDeletedProject(ctx, id)
}

func (hs *HookStore) DeleteEnvironment(ctx context.Context, id uint) error {
	if hk := hs.h.DeleteEnvironment; hk != nil {
		return hk(hs.Storage, ctx, id)
	}
	return hs.Storage.DeleteEnvironment(ctx, id)
}

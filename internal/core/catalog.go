package core

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListProjects returns all projects from storage.
func (c *KeyorixCore) ListProjects(ctx context.Context) ([]*models.Project, error) {
	return c.storage.ListProjects(ctx)
}

// ListEnvironments returns all environments from storage.
func (c *KeyorixCore) ListEnvironments(ctx context.Context) ([]*models.Environment, error) {
	return c.storage.ListEnvironments(ctx)
}

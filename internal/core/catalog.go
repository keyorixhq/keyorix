package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListProjects returns all projects from storage.
func (c *KeyorixCore) ListProjects(ctx context.Context) ([]*models.Project, error) {
	return c.storage.ListProjects(ctx)
}

// ListProjectsWithCounts returns projects with secret and environment counts.
func (c *KeyorixCore) ListProjectsWithCounts(ctx context.Context) ([]storage.ProjectWithCounts, error) {
	return c.storage.ListProjectsWithCounts(ctx)
}

// GetProject returns a single project by ID.
func (c *KeyorixCore) GetProject(ctx context.Context, id uint) (*models.Project, error) {
	return c.storage.GetProject(ctx, id)
}

// UpdateProject updates an existing project's name and description.
func (c *KeyorixCore) UpdateProject(ctx context.Context, id uint, name, description string) (*models.Project, error) {
	if name == "" {
		return nil, fmt.Errorf("project name is required")
	}
	project, err := c.storage.GetProject(ctx, id)
	if err != nil {
		return nil, err
	}
	project.Name = name
	project.Description = description
	return c.storage.UpdateProject(ctx, project)
}

// DeleteProject deletes a project by ID.
// By default (force=false) it returns an error if the project still contains secrets (ADR-019).
// Pass force=true to delete the project and all its secrets (cascade).
func (c *KeyorixCore) DeleteProject(ctx context.Context, id uint, force bool) error {
	if !force {
		projectID := id
		_, total, err := c.storage.ListSecrets(ctx, &storage.SecretFilter{
			ProjectID: &projectID,
			Page:      1,
			PageSize:  1,
		})
		if err != nil {
			return fmt.Errorf("failed to check project secrets: %w", err)
		}
		if total > 0 {
			return fmt.Errorf("project has %d secret(s) — delete them first or use --force to cascade", total)
		}
	}
	return c.storage.DeleteProject(ctx, id)
}

// DeleteEnvironment deletes an environment by ID.
func (c *KeyorixCore) DeleteEnvironment(ctx context.Context, id uint) error {
	return c.storage.DeleteEnvironment(ctx, id)
}

// CreateProject creates a new project and seeds it with default environments.
func (c *KeyorixCore) CreateProject(ctx context.Context, name, description string) (*models.Project, error) {
	if name == "" {
		return nil, fmt.Errorf("project name is required")
	}
	project, err := c.storage.CreateProject(ctx, &models.Project{Name: name, Description: description})
	if err != nil {
		return nil, fmt.Errorf("failed to create project: %w", err)
	}
	// Seed default environments for new project
	for _, envName := range defaultEnvironmentNames {
		_, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: envName, ProjectID: project.ID})
		if err != nil {
			// Non-fatal: log and continue
			_ = err
		}
	}
	return project, nil
}

// ListEnvironments returns all environments from storage.
func (c *KeyorixCore) ListEnvironments(ctx context.Context) ([]*models.Environment, error) {
	return c.storage.ListEnvironments(ctx)
}

// ListEnvironmentsByProject returns environments scoped to a specific project.
func (c *KeyorixCore) ListEnvironmentsByProject(ctx context.Context, projectID uint) ([]*models.Environment, error) {
	return c.storage.ListEnvironmentsByProject(ctx, projectID)
}

// GetEnvironment returns a single environment by ID.
func (c *KeyorixCore) GetEnvironment(ctx context.Context, id uint) (*models.Environment, error) {
	return c.storage.GetEnvironment(ctx, id)
}

// CreateProjectWithEnvs creates a new project seeded with the specified environment names.
// Used when the CLI --envs flag overrides the default development/staging/production set.
func (c *KeyorixCore) CreateProjectWithEnvs(ctx context.Context, name, description string, envNames []string) (*models.Project, error) {
	if name == "" {
		return nil, fmt.Errorf("project name is required")
	}
	project, err := c.storage.CreateProject(ctx, &models.Project{Name: name, Description: description})
	if err != nil {
		return nil, fmt.Errorf("failed to create project: %w", err)
	}
	for _, envName := range envNames {
		if _, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: envName, ProjectID: project.ID}); err != nil {
			_ = err // non-fatal; log and continue
		}
	}
	return project, nil
}

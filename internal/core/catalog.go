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
// When includeDeleted is true, soft-deleted projects are included (flagged via
// the Deleted/DeletedAt fields) for the restore UI.
func (c *KeyorixCore) ListProjectsWithCounts(ctx context.Context, includeDeleted bool) ([]storage.ProjectWithCounts, error) {
	return c.storage.ListProjectsWithCounts(ctx, includeDeleted)
}

// GetProject returns a single project by ID.
func (c *KeyorixCore) GetProject(ctx context.Context, id uint) (*models.Project, error) {
	return c.storage.GetProject(ctx, id)
}

// UpdateProject updates an existing project's name and description, and — when
// requireMFA is non-nil — its per-project MFA requirement (ADR-037). A nil
// requireMFA leaves the flag unchanged (backward-compatible).
func (c *KeyorixCore) UpdateProject(ctx context.Context, id uint, name, description string, requireMFA *bool) (*models.Project, error) {
	if name == "" {
		return nil, fmt.Errorf("project name is required")
	}
	if err := validateDescription(description); err != nil {
		return nil, err
	}
	project, err := c.storage.GetProject(ctx, id)
	if err != nil {
		return nil, err
	}
	mfaChanged := requireMFA != nil && *requireMFA != project.RequireMFA
	project.Name = name
	project.Description = description
	if requireMFA != nil {
		project.RequireMFA = *requireMFA
	}
	updated, err := c.storage.UpdateProject(ctx, project)
	if err != nil {
		return nil, err
	}
	if mfaChanged {
		pid := id
		state := "disabled"
		if *requireMFA {
			state = "enabled"
		}
		c.writeAuditEventFull(ctx, "project.mfa_requirement_"+state, nil, nil, &pid, "",
			fmt.Sprintf("per-project MFA requirement %s for project %q", state, updated.Name))
	}
	return updated, nil
}

// ProjectRequiresMFA reports whether the project enforces a per-project MFA
// requirement (ADR-037). A missing project is treated as not requiring MFA.
func (c *KeyorixCore) ProjectRequiresMFA(ctx context.Context, projectID uint) (bool, error) {
	project, err := c.storage.GetProject(ctx, projectID)
	if err != nil {
		return false, err
	}
	return project.RequireMFA, nil
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

// RestoreProject reverses a soft-delete, bringing back the project and the
// environments and secrets that were removed with it. actorID is the acting admin
// (0 = none). Audited as project.restored, with a per-type count of what the
// cascade actually resurrected (#311) — the storage layer already refuses to touch
// children retired independently of the project (see LocalStorage.RestoreProject's
// deletion-timestamp correlation), but the single generic event previously gave no
// way to tell HOW MANY environments/secrets came back, so a DR-test or accidental
// delete-then-undo left no forensic trail distinguishing "1 secret" from "200".
func (c *KeyorixCore) RestoreProject(ctx context.Context, actorID, id uint) error {
	envCount, secretCount, err := c.storage.RestoreProject(ctx, id)
	if err != nil {
		return err
	}
	pid := id
	c.writeAuditEventFull(ctx, "project.restored", actorPtr(actorID), nil, &pid, "",
		fmt.Sprintf("project %d restored (cascade resurrected %d environment(s) and %d secret(s))", id, envCount, secretCount))
	return nil
}

// DeleteEnvironment deletes an environment by ID.
func (c *KeyorixCore) DeleteEnvironment(ctx context.Context, id uint) error {
	return c.storage.DeleteEnvironment(ctx, id)
}

// RestoreEnvironment clears the soft-delete on an environment, scoped to
// projectID so a caller authorized for one project cannot restore another's.
// actorID is the acting admin (0 = none). Audited as environment.restored.
func (c *KeyorixCore) RestoreEnvironment(ctx context.Context, actorID, projectID, id uint) error {
	if err := c.storage.RestoreEnvironment(ctx, projectID, id); err != nil {
		return err
	}
	pid := projectID
	c.writeAuditEventFull(ctx, "environment.restored", actorPtr(actorID), nil, &pid, "", fmt.Sprintf("environment %d restored in project %d", id, projectID))
	return nil
}

// CreateProject creates a new project and seeds it with default environments.
func (c *KeyorixCore) CreateProject(ctx context.Context, name, description string) (*models.Project, error) {
	if name == "" {
		return nil, fmt.Errorf("project name is required")
	}
	if err := validateDescription(description); err != nil {
		return nil, err
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

// ListEnvironmentsByProjectIncludingDeleted returns a project's environments,
// including soft-deleted ones, for the restore UI.
func (c *KeyorixCore) ListEnvironmentsByProjectIncludingDeleted(ctx context.Context, projectID uint) ([]*models.Environment, error) {
	return c.storage.ListEnvironmentsByProjectIncludingDeleted(ctx, projectID)
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
	if err := validateDescription(description); err != nil {
		return nil, err
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

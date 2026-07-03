package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #383: bounds on the project/environment catalog so a single request can't blow
// past a reasonable working set. maxEnvNamesPerCreate is generous relative to
// defaultEnvironmentNames' 3-entry convention — a few dozen covers realistic
// per-region/per-service environment fan-out — while still keeping
// CreateProjectWithEnvs's loop bounded instead of open to a ~10 MiB request body
// (a JSON array entry as short as `"a",` fits roughly 1-2 million times in that
// budget) requesting on the order of a million environments in one call.
// maxProjectNameLen/maxEnvironmentNameLen cap the unbounded `Name` text columns
// (Project.Name/Environment.Name) so an oversized name can't compound the same
// row/index bloat; a few hundred characters is generous for a name field.
const (
	maxEnvNamesPerCreate  = 50
	maxProjectNameLen     = 200
	maxEnvironmentNameLen = 200
)

// validateProjectName bounds Project.Name (#383): required, and capped so an
// unbounded text column can't be used to bloat storage/index size.
func validateProjectName(name string) error {
	if name == "" {
		return fmt.Errorf("%s: project name is required", i18n.T("ErrorValidation", nil))
	}
	if len(name) > maxProjectNameLen {
		return fmt.Errorf("%s: project name exceeds %d characters", i18n.T("ErrorValidation", nil), maxProjectNameLen)
	}
	return nil
}

// validateEnvironmentName bounds Environment.Name (#383), mirroring validateProjectName.
func validateEnvironmentName(name string) error {
	if name == "" {
		return fmt.Errorf("%s: environment name is required", i18n.T("ErrorValidation", nil))
	}
	if len(name) > maxEnvironmentNameLen {
		return fmt.Errorf("%s: environment name exceeds %d characters", i18n.T("ErrorValidation", nil), maxEnvironmentNameLen)
	}
	return nil
}

// translateProjectNameError surfaces storage.ErrDuplicateProjectName (#385, the
// case-insensitive partial unique index on projects.name) as a clean "name already in
// use" validation error, mirroring CreateUser's translation of ErrDuplicateEmail (#117),
// rather than letting a raw constraint-violation message reach the caller.
func translateProjectNameError(err error) error {
	if errors.Is(err, storage.ErrDuplicateProjectName) {
		return fmt.Errorf("%s: a project with this name already exists", i18n.T("ErrorValidation", nil))
	}
	return err
}

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
	if err := validateProjectName(name); err != nil {
		return nil, err
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
		return nil, translateProjectNameError(err)
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
	// #313: the guard count and the cascade delete used to be two separate top-level
	// storage calls, with core-layer control flow in between — a secret created in that
	// window silently got swept into the cascade despite the caller expecting the delete
	// to be rejected. Run the guard and the delete inside one transaction (a nested
	// savepoint over LocalStorage.DeleteProject's own transaction) so the count that
	// gates the reject is the same one the cascade acts on, not a stale read.
	return c.storage.WithTransaction(ctx, func(tx storage.Storage) error {
		if !force {
			projectID := id
			_, total, err := tx.ListSecrets(ctx, &storage.SecretFilter{
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
		return tx.DeleteProject(ctx, id)
	})
}

// RestoreProject reverses a soft-delete, bringing back the project and the
// environments and secrets that were removed with it. actorID is the acting admin
// (0 = none). Audited as project.restored, with a per-type count of what the
// cascade actually resurrected (#311) — the storage layer already refuses to touch
// children retired independently of the project (see LocalStorage.RestoreProject's
// deletion-timestamp correlation), but the single generic event previously gave no
// way to tell HOW MANY environments/secrets came back, so a DR-test or accidental
// delete-then-undo left no forensic trail distinguishing "1 secret" from "200".
//
// #161: restoring reinstates every role bound to the project (any environment), so
// before restoring, this checks that aggregate role SET against the actor's own
// authority — the same treatment #147 applies to group restore. See
// requireGlobalAdminToReinstateAdminRoles.
func (c *KeyorixCore) RestoreProject(ctx context.Context, actorID, id uint) error {
	if err := c.requireAuthorityToReinstateProjectRoles(ctx, actorID, id, "project"); err != nil {
		return err
	}
	envCount, secretCount, err := c.storage.RestoreProject(ctx, id)
	if err != nil {
		return err
	}
	pid := id
	c.writeAuditEventFull(ctx, "project.restored", actorPtr(actorID), nil, &pid, "",
		fmt.Sprintf("project %d restored (cascade resurrected %d environment(s) and %d secret(s))", id, envCount, secretCount))
	return nil
}

// requireAuthorityToReinstateProjectRoles collects every role bound directly to
// projectID (any environment, user or group grant) and refuses if that set
// contains an admin-tier role the actor cannot themselves match. Shared by
// RestoreProject and RestoreEnvironment (an environment's role grants are a
// subset of its project's).
func (c *KeyorixCore) requireAuthorityToReinstateProjectRoles(ctx context.Context, actorID, projectID uint, objectDesc string) error {
	assignments, err := c.storage.ListProjectRoleAssignments(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to resolve project role grants: %w", err)
	}
	roleIDs := make([]uint, 0, len(assignments))
	for _, a := range assignments {
		roleIDs = append(roleIDs, a.RoleID)
	}
	return c.requireGlobalAdminToReinstateAdminRoles(ctx, actorID, roleIDs, objectDesc)
}

// DeleteEnvironment deletes an environment by ID.
func (c *KeyorixCore) DeleteEnvironment(ctx context.Context, id uint) error {
	return c.storage.DeleteEnvironment(ctx, id)
}

// RestoreEnvironment clears the soft-delete on an environment, scoped to
// projectID so a caller authorized for one project cannot restore another's.
// actorID is the acting admin (0 = none). Audited as environment.restored.
//
// #161: see RestoreProject — the same aggregate role-set ceiling check applies,
// scoped to the owning project (the environment's own grants are a subset of it).
func (c *KeyorixCore) RestoreEnvironment(ctx context.Context, actorID, projectID, id uint) error {
	if err := c.requireAuthorityToReinstateProjectRoles(ctx, actorID, projectID, "environment"); err != nil {
		return err
	}
	if err := c.storage.RestoreEnvironment(ctx, projectID, id); err != nil {
		return err
	}
	pid := projectID
	c.writeAuditEventFull(ctx, "environment.restored", actorPtr(actorID), nil, &pid, "", fmt.Sprintf("environment %d restored in project %d", id, projectID))
	return nil
}

// CreateProject creates a new project and seeds it with default environments.
func (c *KeyorixCore) CreateProject(ctx context.Context, name, description string) (*models.Project, error) {
	if err := validateProjectName(name); err != nil {
		return nil, err
	}
	if err := validateDescription(description); err != nil {
		return nil, err
	}
	project, err := c.storage.CreateProject(ctx, &models.Project{Name: name, Description: description})
	if err != nil {
		if errors.Is(err, storage.ErrDuplicateProjectName) {
			return nil, translateProjectNameError(err)
		}
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

// CreateEnvironment creates a single environment under an existing project,
// validating the name (#383). This is the single-environment counterpart to
// CreateProjectWithEnvs's fan-out create; callers (the HTTP
// POST /projects/{id}/environments handler, the `keyorix project env create`
// CLI) previously wrote straight to storage, bypassing any name-length guard.
func (c *KeyorixCore) CreateEnvironment(ctx context.Context, projectID uint, name string) (*models.Environment, error) {
	if err := validateEnvironmentName(name); err != nil {
		return nil, err
	}
	return c.storage.CreateEnvironment(ctx, &models.Environment{ProjectID: projectID, Name: name})
}

// CreateProjectWithEnvs creates a new project seeded with the specified environment names.
// Used when the CLI --envs flag overrides the default development/staging/production set.
func (c *KeyorixCore) CreateProjectWithEnvs(ctx context.Context, name, description string, envNames []string) (*models.Project, error) {
	if err := validateProjectName(name); err != nil {
		return nil, err
	}
	if err := validateDescription(description); err != nil {
		return nil, err
	}
	// #383: cap the environment fan-out before touching storage at all — without
	// this, a single ~10 MiB request (a JSON array entry as short as `"a",` fits
	// roughly 1-2 million times in that budget) could request on the order of a
	// million environments, degrading the shared install for every other tenant.
	if len(envNames) > maxEnvNamesPerCreate {
		return nil, fmt.Errorf("%s: at most %d environments per project create (got %d)",
			i18n.T("ErrorValidation", nil), maxEnvNamesPerCreate, len(envNames))
	}
	for _, envName := range envNames {
		if err := validateEnvironmentName(envName); err != nil {
			return nil, err
		}
	}
	project, err := c.storage.CreateProject(ctx, &models.Project{Name: name, Description: description})
	if err != nil {
		if errors.Is(err, storage.ErrDuplicateProjectName) {
			return nil, translateProjectNameError(err)
		}
		return nil, fmt.Errorf("failed to create project: %w", err)
	}
	for _, envName := range envNames {
		if _, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: envName, ProjectID: project.ID}); err != nil {
			_ = err // non-fatal; log and continue
		}
	}
	return project, nil
}

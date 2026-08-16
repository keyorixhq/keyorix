package core

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

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

// identifierRegex is the anti-homograph/anti-spoofing charset guard (G38):
// letters, digits, spaces, hyphens, and underscores only — no zero-width
// characters, no mixed-script confusables, no control characters. Ported
// verbatim from server/validation/validator.go's identical `identifier` rule.
// Before this fix, this charset check was enforced ONLY by the HTTP JSON
// decoder's `validate:"identifier"` struct tag on the request body — the
// gRPC service layer and CLI embedded-mode path, which construct a Project
// directly without ever routing through that HTTP-specific validator, could
// create a project whose name silently smuggled a confusable/spoofed
// character sequence past every UI and audit log that assumes the HTTP path
// already sanitized it. Duplicated here (not imported from server/validation)
// to keep internal/core independent of the server/* packages that depend on
// it, matching this file's existing validateProjectName/validateEnvironmentName
// convention.
var identifierRegex = regexp.MustCompile(`^[a-zA-Z0-9 _-]+$`)

func validateIdentifier(name string) error {
	if !identifierRegex.MatchString(name) {
		return fmt.Errorf("%s: must contain only letters, digits, spaces, - or _", i18n.T("ErrorValidation", nil))
	}
	// Mirrors server/validation/validator.go's validateIdentifier: reject
	// whitespace variants that pass the charset check above but defeat the
	// anti-spoofing intent — all-whitespace, leading/trailing whitespace, or
	// repeated internal whitespace (e.g. "Support Team" vs "Support  Team").
	if trimmed := strings.TrimSpace(name); trimmed == "" || trimmed != name || strings.Contains(trimmed, "  ") {
		return fmt.Errorf("%s: must not be all whitespace or have leading, trailing, or repeated internal whitespace", i18n.T("ErrorValidation", nil))
	}
	return nil
}

// validateProjectName bounds Project.Name (#383): required, and capped so an
// unbounded text column can't be used to bloat storage/index size. Also
// enforces the anti-homograph identifier charset (G38) — see validateIdentifier.
func validateProjectName(name string) error {
	if name == "" {
		return fmt.Errorf("%s: project name is required", i18n.T("ErrorValidation", nil))
	}
	if len(name) > maxProjectNameLen {
		return fmt.Errorf("%s: project name exceeds %d characters", i18n.T("ErrorValidation", nil), maxProjectNameLen)
	}
	return validateIdentifier(name)
}

// validateEnvironmentName bounds Environment.Name (#383), mirroring
// validateProjectName. Also enforces the anti-homograph identifier charset
// (G38) — see validateIdentifier. Environment names were previously missed by
// G38's project-name fix, so a confusable/spoofed environment name could
// still slip past every transport (gRPC, CLI embedded mode), not just HTTP.
func validateEnvironmentName(name string) error {
	if name == "" {
		return fmt.Errorf("%s: environment name is required", i18n.T("ErrorValidation", nil))
	}
	if len(name) > maxEnvironmentNameLen {
		return fmt.Errorf("%s: environment name exceeds %d characters", i18n.T("ErrorValidation", nil), maxEnvironmentNameLen)
	}
	return validateIdentifier(name)
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
//
// #369: the storage-layer cascade (LocalStorage.DeleteProject) also disables every
// dynamic-secret config scoped to the project in the same transaction, so IssueLease/
// RenewLease refuse to touch it from the instant the delete commits. Once that commits,
// this revokes every active (and previously revoke_failed) lease under those configs
// against their real targets — deliberately AFTER the transaction, and best-effort: each
// call is real network I/O to an operator-defined external database, which must not hold
// a DB transaction open, and a target being unreachable must not block the project delete
// itself (the lease stays revoke_failed/retryable, same as any other RevokeLeasesForConfig
// use, and is reachable again via the sweep or a manual retry once the target recovers).
func (c *KeyorixCore) DeleteProject(ctx context.Context, id uint, force bool) error {
	// #313 / #528: the guard count and the cascade delete must not run as two separate
	// top-level storage calls with core-layer control flow in between — a secret created
	// in that window would silently get swept into the cascade despite the caller
	// expecting the delete to be rejected. #313 originally closed this by running both
	// inside one storage.WithTransaction call; #528 replaced that with
	// DeleteProjectIfEmpty, a single atomic storage primitive doing the same guard+
	// cascade in ONE call — WithTransaction is a real transaction only for LocalStorage
	// (RemoteStorage.WithTransaction is a no-op passthrough over HTTP, so the original
	// two-call pair reopened this exact TOCTOU window across a full network round trip
	// under storage.type: remote). force=true intentionally skips the guard entirely and
	// keeps calling the plain unconditional cascade.
	if force {
		if err := c.storage.DeleteProject(ctx, id); err != nil {
			return err
		}
	} else {
		blocking, err := c.storage.DeleteProjectIfEmpty(ctx, id)
		if err != nil {
			return err
		}
		if blocking > 0 {
			return fmt.Errorf("project has %d secret(s) — delete them first or use --force to cascade", blocking)
		}
	}
	c.revokeProjectDynamicSecretLeases(ctx, id)
	return nil
}

// revokeProjectDynamicSecretLeases is DeleteProject's post-commit dynamic-secrets
// cascade (#369): it revokes every active lease under every dynamic-secret config
// scoped to id (the config rows themselves were already marked Disabled inside
// DeleteProject's transaction). Best-effort and system-actored (userID 0, like the
// expiry sweep) — a target-side revoke failure is recorded per-lease (revoke_failed,
// retryable) by RevokeLeasesForConfig and must not fail project deletion itself, which
// has already committed by the time this runs.
func (c *KeyorixCore) revokeProjectDynamicSecretLeases(ctx context.Context, projectID uint) {
	configs, err := c.storage.ListDynamicSecretConfigs(ctx, projectID, 0)
	if err != nil {
		c.writeAuditEventFull(ctx, "dynamic_secret.project_cascade_failed", nil, nil, &projectID, "",
			fmt.Sprintf("failed to list dynamic-secret configs to revoke after project %d deletion: %v — revoke them manually", projectID, err))
		return
	}
	if len(configs) == 0 {
		return
	}
	var revokedTotal, failedTotal int
	for _, cfg := range configs {
		revoked, failed, rerr := c.RevokeLeasesForConfig(ctx, cfg.ID, 0, "project deleted")
		if rerr != nil {
			// RevokeLeasesForConfig only errors on a failure to even list the config's
			// leases (not on a per-lease target failure, which it counts in `failed`
			// instead) — still non-fatal here; audited below alongside the summary.
			failedTotal++
			continue
		}
		revokedTotal += revoked
		failedTotal += failed
	}
	c.writeAuditEventFull(ctx, "dynamic_secret.project_cascade_revoke", nil, nil, &projectID, "",
		fmt.Sprintf("project %d delete disabled %d dynamic-secret config(s) and revoked %d active lease(s) (%d failed — see per-lease audit)",
			projectID, len(configs), revokedTotal, failedTotal))
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
//
// #369: unlike secrets/environments, this deliberately does NOT re-enable the
// project's dynamic-secret configs that DeleteProject's cascade disabled. A
// resurrected dynamic-secret config can immediately mint live database
// credentials against a real external target the instant it's re-enabled — a
// materially higher-consequence "silent resurrection" than a restored static
// secret (whose value is inert until read). Leaving configs disabled-until-
// manually-re-enabled means an admin must make an explicit, auditable decision
// (SetDynamicSecretConfigEnabled, per config) rather than a bulk project
// restore quietly reinstating database-credential issuance nobody explicitly
// asked to bring back. Restoring leases themselves is not on the table at all
// — they were revoked against the real target, not just marked; there is no
// "credential" left to restore.
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
//
// storage.Storage's GetEnvironment/DeleteEnvironment take a bare, unscoped id
// (unlike RestoreEnvironment, which is deliberately project-scoped) because
// some legitimate callers don't yet know which project an id belongs to and
// use this to find out (e.g. server/middleware.ScopeFromEnvParam resolving an
// authorization scope from a URL id, or the read-only display-name cache in
// permission_matrix.go). Callers that already believe an environment belongs
// to a specific project — and would silently operate on the wrong tenant's
// environment if that belief were wrong — must use GetEnvironmentInProject
// below instead of calling this (or storage.GetEnvironment) directly.
func (c *KeyorixCore) GetEnvironment(ctx context.Context, id uint) (*models.Environment, error) {
	return c.storage.GetEnvironment(ctx, id)
}

// GetEnvironmentInProject returns an environment by id, but only if it
// actually belongs to projectID — the project-scoped counterpart to the bare
// GetEnvironment above, mirroring the scoping storage.Storage.RestoreEnvironment
// already gets from its signature. Use this (not GetEnvironment) whenever a
// caller already has a projectID in hand (from a nested URL path, a request
// body field, an active CLI project context, etc.) and is about to look up or
// act on an environment it BELIEVES belongs to that project — so a bare-id
// mismatch (the environment actually belongs to a different project) is
// refused instead of silently operating cross-tenant.
//
// Returns a generic "environment not found" error (not a distinct "wrong
// project" error) on mismatch, matching storage.GetEnvironment's own
// not-found error and RestoreEnvironment's WHERE-clause behavior, so a caller
// without access to project B can't use this to probe whether a given
// environment id exists there.
func (c *KeyorixCore) GetEnvironmentInProject(ctx context.Context, projectID, id uint) (*models.Environment, error) {
	env, err := c.storage.GetEnvironment(ctx, id)
	if err != nil {
		return nil, err
	}
	if env.ProjectID != projectID {
		return nil, fmt.Errorf("environment not found")
	}
	return env, nil
}

// CreateEnvironment creates a single environment under an existing project,
// validating the name (#383). This is the single-environment counterpart to
// CreateProjectWithEnvs's fan-out create; callers (the HTTP
// POST /projects/{id}/environments handler, the `keyorix project env create`
// CLI) previously wrote straight to storage, bypassing any name-length guard.
//
// G38: also confirms projectID names a LIVE (non-soft-deleted) project before
// creating anything under it. The HTTP handler's own scope middleware resolves
// projectID from the URL without verifying the project still exists, so
// without this check here, a caller who still held write authority on a
// since-soft-deleted project (RBAC grants aren't retroactively revoked by a
// project delete) could re-establish a usable environment/scope under it —
// storage.GetProject excludes soft-deleted projects, so this fails closed the
// same way the HTTP handler's own defense-in-depth check already does, but
// now for every transport (gRPC, CLI embedded mode) instead of only HTTP.
func (c *KeyorixCore) CreateEnvironment(ctx context.Context, projectID uint, name string) (*models.Environment, error) {
	if err := validateEnvironmentName(name); err != nil {
		return nil, err
	}
	if _, err := c.storage.GetProject(ctx, projectID); err != nil {
		return nil, fmt.Errorf("%s: project not found", i18n.T("ErrorNotFound", nil))
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

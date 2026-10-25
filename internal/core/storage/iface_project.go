package storage

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ProjectStore is the Storage slice for projects and environments.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type ProjectStore interface {
	// Project / Environment management
	CreateProject(ctx context.Context, project *models.Project) (*models.Project, error)
	GetProject(ctx context.Context, id uint) (*models.Project, error)
	// UpdateProjectFields persists ONLY name, description and updated_at — plus
	// require_mfa when (and only when) requireMFA is non-nil — onto a LIVE
	// project row: "UPDATE projects SET ... WHERE id = ? AND deleted_at IS
	// NULL". matched=false (no error) means the project is gone; the caller must
	// not report success.
	//
	// This REPLACES the former UpdateProject, a bare GORM Save of a struct the
	// caller read earlier (#2697). Two consequences, both closed by the shape
	// above rather than by the caller being careful:
	//   - Save's 0-rows fallback is an upsert that writes deleted_at = NULL, so
	//     a rename landing after DeleteProject resurrected the project row
	//     alone (its secrets and environments stayed deleted), after which
	//     requireLiveProject and the RestoreSecret/RestoreEnvironment liveness
	//     checks passed again for project-scoped grant holders;
	//   - Save wrote every column, so a plain rename whose read predated an
	//     admin enabling ADR-037's per-project require_mfa wrote `false` back
	//     over it — no roles.assign needed, and no audit event, because
	//     core.UpdateProject only audits when ITS OWN argument changes the
	//     value it read. requireMFA is a pointer here so "I am not changing
	//     this flag" is expressible, and a nil one never reaches the UPDATE.
	UpdateProjectFields(ctx context.Context, id uint, name, description string, requireMFA *bool, updatedAt time.Time) (matched bool, err error)
	DeleteProject(ctx context.Context, id uint) error
	// DeleteProjectIfEmpty atomically enforces DeleteProject(force=false)'s guard —
	// reject the delete if the project still has any live secret — and, only when the
	// project IS empty, performs the SAME cascade soft-delete DeleteProject does, all as
	// ONE storage operation (#528). It replaces core.DeleteProject's prior
	// WithTransaction-wrapped ListSecrets+DeleteProject pair (#313): that pair depended
	// on WithTransaction opening a REAL transaction to keep the guard's read and the
	// cascade's write atomic, which held for LocalStorage but NOT for the now-deleted
	// RemoteStorage — its WithTransaction was a no-op passthrough over HTTP (see its doc
	// comment above), so a naive two-call proxy of that same pair would have reopened a
	// TOCTOU window across a full network round trip: a secret created between the count
	// and the cascade would silently let a force=false delete cascade over it anyway, the
	// same check-then-act-split-by-a-non-transactional-WithTransaction bug class this
	// campaign has already hit repeatedly. Folding the guard and the cascade into one call
	// closed that gap; under LocalStorage it is (and always was) one DB transaction.
	// Returns the count of live secrets blocking the delete (0 means the
	// delete happened) so the caller can format the same "project has N secret(s)..."
	// error DeleteProject(force=false) has always returned.
	DeleteProjectIfEmpty(ctx context.Context, id uint) (blockingSecretCount int, err error)
	// RestoreProject reverses a project soft-delete and cascades to the environments/
	// secrets that were removed WITH it (matched by deletion timestamp — independently
	// retired children stay deleted, see LocalStorage.RestoreProject). It returns the
	// count of environments and secrets the cascade actually restored, so the caller
	// can audit what came back (#311), not just that "the project" was restored.
	RestoreProject(ctx context.Context, id uint) (restoredEnvironments, restoredSecrets int, err error)
	// SuspendMachineIdentitiesForDeletedProject (#3433) suspends every ACTIVE machine
	// identity that belongs to soft-deleted project id (home project, or a role there)
	// and holds no role in any other live project (or at global scope), stamping each
	// with the project's id and deleted_at (models.MachineIdentity.CascadeSuspended*).
	// It returns the identities it suspended. It refuses a live project. Call it in the
	// same transaction as DeleteProject/DeleteProjectIfEmpty, after the cascade.
	SuspendMachineIdentitiesForDeletedProject(ctx context.Context, id uint) ([]*models.MachineIdentity, error)
	// ReactivateMachineIdentitiesForRestoredProject (#3433) re-activates exactly the
	// identities the CURRENT soft-delete of project id suspended and nothing has written
	// since (marker equals the project's deleted_at, updated_at unchanged), clearing the
	// marker, and returns them. Call it in the same transaction as RestoreProject,
	// BEFORE it: it needs the project still deleted. It refuses a live project.
	ReactivateMachineIdentitiesForRestoredProject(ctx context.Context, id uint, now time.Time) ([]*models.MachineIdentity, error)
	ListProjects(ctx context.Context) ([]*models.Project, error)
	ListProjectsWithCounts(ctx context.Context, includeDeleted bool) ([]ProjectWithCounts, error)
	CreateEnvironment(ctx context.Context, env *models.Environment) (*models.Environment, error)
	GetEnvironment(ctx context.Context, id uint) (*models.Environment, error)
	DeleteEnvironment(ctx context.Context, id uint) error
	// RestoreEnvironment restores a soft-deleted environment, scoped to projectID
	// so a caller authorized for one project cannot restore another's environment.
	RestoreEnvironment(ctx context.Context, projectID, id uint) error
	ListEnvironments(ctx context.Context) ([]*models.Environment, error)
	ListEnvironmentsByProject(ctx context.Context, projectID uint) ([]*models.Environment, error)
	ListEnvironmentsByProjectIncludingDeleted(ctx context.Context, projectID uint) ([]*models.Environment, error)
}

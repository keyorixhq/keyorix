// local_secrets.go — Secret node and version operations for LocalStorage.
//
// Covers: CreateSecret, GetSecret, GetSecretByName, UpdateSecret, DeleteSecret,
//
//	ListSecrets, CreateSecretVersion, GetSecretVersion (via GORM),
//	GetSecretVersions, GetLatestSecretVersion, IncrementSecretReadCount,
//	Project/Environment CRUD.
//
// All operations use direct GORM queries; no network calls.
// For the remote (HTTP) equivalent see remote_secrets.go.
package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// --- Project / Environment ---

// maxEnvironmentListing caps how many environments a single ListEnvironmentsByProject
// (or ...IncludingDeleted) call returns (#386). This is defense-in-depth behind the
// creation-time cap on CreateProjectWithEnvs (#383, maxEnvNamesPerCreate in
// internal/core/catalog.go): that cap bounds a single fan-out create, but a project
// can still accrete environments one at a time via repeated single-environment-create
// calls, and this backstop keeps the listing query/response bounded independent of
// that limit — including for any pre-existing data created before #383 shipped. Set
// well above the create-time cap so it never trips under normal use.
const maxEnvironmentListing = 1000

// isDuplicateProjectNameViolation reports whether err is a unique-constraint violation
// on specifically the partial projects-name index (uniq_projects_name_active, #385), as
// distinct from any other unique constraint. Both SQLite and Postgres include the
// violated index name in the driver-native error text for an expression index like this
// one, mirroring isDuplicateEmailViolation's treatment of users.email (#117).
func isDuplicateProjectNameViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "uniq_projects_name_active")
}

func (ls *LocalStorage) CreateProject(ctx context.Context, project *models.Project) (*models.Project, error) {
	if err := ls.db.WithContext(ctx).Create(project).Error; err != nil {
		if isDuplicateProjectNameViolation(err) {
			// The partial unique index uniq_projects_name_active (#385) caught a
			// case-insensitive duplicate: another project already holds this name (in any
			// case). Translate to the sentinel so callers can surface a clean "project name
			// already in use" error instead of a raw constraint-violation message.
			return nil, fmt.Errorf("%w: %v", storage.ErrDuplicateProjectName, err)
		}
		return nil, err
	}
	return project, nil
}

func (ls *LocalStorage) CreateEnvironment(ctx context.Context, env *models.Environment) (*models.Environment, error) {
	return env, ls.db.WithContext(ctx).Create(env).Error
}

func (ls *LocalStorage) ListProjects(ctx context.Context) ([]*models.Project, error) {
	var projects []*models.Project
	return projects, ls.db.WithContext(ctx).Find(&projects).Error
}

// ListProjectsWithCounts returns projects with aggregated secret and environment
// counts. Soft-deleted projects (and their secrets/environments in the counts)
// are excluded unless includeDeleted is true — this query uses raw SQL, which
// bypasses GORM's soft-delete scope, so the deleted_at filters are explicit.
func (ls *LocalStorage) ListProjectsWithCounts(ctx context.Context, includeDeleted bool) ([]storage.ProjectWithCounts, error) {
	type row struct {
		ID                 uint
		Name               string
		Description        string
		SecretCount        int64
		EnvironmentCount   int64
		DeletedAt          *string
		CreatedAt          string
		UpdatedAt          string
		LastSecretActivity *string
	}
	// Both where values are compile-time string constants — no user input is
	// interpolated. Do NOT add user-controlled filter terms to this query without
	// switching to parameterised bindings.
	where := "WHERE p.deleted_at IS NULL"
	if includeDeleted {
		where = ""
	}
	var rows []row
	err := ls.db.WithContext(ctx).Raw(`
		SELECT p.id, p.name, p.description, p.created_at, p.updated_at, p.deleted_at,
		       COUNT(DISTINCT s.id) AS secret_count,
		       COUNT(DISTINCT e.id) AS environment_count,
		       MAX(s.updated_at) AS last_secret_activity
		FROM projects p
		LEFT JOIN secret_nodes s ON s.project_id = p.id AND s.deleted_at IS NULL
		LEFT JOIN environments e ON e.project_id = p.id AND e.deleted_at IS NULL
		` + where + `
		GROUP BY p.id
		ORDER BY p.id
	`).Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("failed to list projects with counts: %w", err)
	}
	result := make([]storage.ProjectWithCounts, 0, len(rows))
	for _, r := range rows {
		pc := storage.ProjectWithCounts{
			ID:               r.ID,
			Name:             r.Name,
			Description:      r.Description,
			SecretCount:      r.SecretCount,
			EnvironmentCount: r.EnvironmentCount,
		}
		// Last activity = most recent of the project's own update or any of its
		// secrets' updates. Computed in Go (not SQL GREATEST) so the query works
		// on both Postgres and the SQLite-backed tests; the two columns share a
		// format within a given DB, so a lexical compare is a valid time compare.
		pc.LastActivity = r.UpdatedAt
		if r.LastSecretActivity != nil && *r.LastSecretActivity > pc.LastActivity {
			pc.LastActivity = *r.LastSecretActivity
		}
		if r.DeletedAt != nil {
			pc.Deleted = true
			pc.DeletedAt = *r.DeletedAt
		}
		result = append(result, pc)
	}
	return result, nil
}

func (ls *LocalStorage) GetProject(ctx context.Context, id uint) (*models.Project, error) {
	var project models.Project
	if err := ls.db.WithContext(ctx).First(&project, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("project not found")
		}
		return nil, fmt.Errorf("failed to get project: %w", err)
	}
	return &project, nil
}

// GetProjectByName resolves a project by name, case-insensitively — matching
// ensureProjectNameIndex's LOWER(name) partial unique index exactly, so this can
// never resolve two different rows for names differing only in case. GORM's
// soft-delete scoping (Project.DeletedAt) already excludes a soft-deleted project
// from this query without an explicit deleted_at clause, consistent with a deleted
// project's name being freed for reuse (see Project.Name's own doc comment) — this
// must never resolve a name to a row that no longer legitimately holds it.
func (ls *LocalStorage) GetProjectByName(ctx context.Context, name string) (*models.Project, error) {
	var project models.Project
	if err := ls.db.WithContext(ctx).Where("LOWER(name) = LOWER(?)", name).First(&project).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("project not found")
		}
		return nil, fmt.Errorf("failed to get project by name: %w", err)
	}
	return &project, nil
}

func (ls *LocalStorage) UpdateProject(ctx context.Context, project *models.Project) (*models.Project, error) {
	if err := ls.db.WithContext(ctx).Save(project).Error; err != nil {
		if isDuplicateProjectNameViolation(err) {
			// See CreateProject's comment: a rename collided with the partial
			// case-insensitive unique index (#385).
			return nil, fmt.Errorf("%w: %v", storage.ErrDuplicateProjectName, err)
		}
		return nil, fmt.Errorf("failed to update project: %w", err)
	}
	return project, nil
}

// deleteProjectCascade performs DeleteProject's soft-delete cascade (secrets, their
// shares, environments, dynamic-secret configs, then the project itself) against tx —
// the transaction-scoped *gorm.DB the caller (DeleteProject or DeleteProjectIfEmpty,
// #528) is already running inside. Factored out of DeleteProject so
// DeleteProjectIfEmpty can run the exact SAME cascade, inside its own transaction,
// immediately after its own empty-project check, without duplicating this logic or
// splitting the check and the cascade across two top-level storage calls.
func deleteProjectCascade(tx *gorm.DB, id uint) error {
	// Stamp the project and the rows the cascade soft-deletes with ONE uniform
	// deleted_at, so RestoreProject can bring back exactly this cascade's rows and not
	// resurrect secrets/environments that were retired independently earlier (which
	// carry a different, earlier deleted_at). GORM auto-scopes Update on a soft-delete
	// model to deleted_at IS NULL, so already-deleted children are left untouched and
	// keep their original timestamp.
	deletedAt := time.Now()
	// Soft-delete all currently-live secrets in the project.
	if err := tx.Model(&models.SecretNode{}).
		Where(sqlWhereProjectID, id).Update("deleted_at", deletedAt).Error; err != nil {
		return fmt.Errorf("failed to soft-delete project secrets: %w", err)
	}
	// Revoke every still-active share for every secret in this project (#119
	// residual): the bulk update above is a raw UPDATE on secret_nodes, unlike
	// DeleteSecret's per-secret path, which also revokes that secret's ShareRecord
	// rows (#370) — so a project-cascade delete used to skip that step entirely,
	// leaving shares for the project's secrets live. Left alone, a share would
	// silently reactivate (via CheckSharePermission) the instant the project (and
	// its secrets) is later restored, with zero re-authorization — exactly the
	// hazard #370 closed for a single secret delete. The subquery is raw SQL,
	// deliberately bypassing GORM's default deleted_at IS NULL scope on
	// SecretNode, so it also reaches the secrets just soft-deleted above. Mirrors
	// #370: like RestoreSecret, RestoreProject does NOT bring these shares back —
	// "delete means gone" for sharing, whether the secret was deleted directly or
	// via a project cascade.
	if err := tx.Where("secret_id IN (SELECT id FROM secret_nodes WHERE project_id = ?) AND deleted_at IS NULL", id).
		Delete(&models.ShareRecord{}).Error; err != nil {
		return fmt.Errorf("failed to revoke project secret shares: %w", err)
	}
	// UserRole/GroupRole grants scoped to this project are deliberately left
	// untouched here, unlike ShareRecord above. Both are plain composite-primary-key
	// join rows (UserID/GroupID, RoleID, ProjectID, EnvironmentID) with no DeletedAt
	// column of their own — soft-deleting them isn't possible without a schema
	// migration that also reworks their primary key (a soft-deleted grant would
	// collide with a later re-grant of the identical scope under today's PK), and
	// RestoreProject's design (see requireAuthorityToReinstateProjectRoles / #161)
	// depends on these rows surviving the soft-delete window unchanged so a restore
	// fully reinstates the project's prior grants, gated by the actor's own
	// authority. PurgeDeletedProjectsBefore already hard-deletes them once the
	// project passes its retention window and can no longer be restored — the same
	// cascade, just necessarily deferred until undo is off the table.
	//
	// Soft-delete all currently-live environments in the project.
	if err := tx.Model(&models.Environment{}).
		Where(sqlWhereProjectID, id).Update("deleted_at", deletedAt).Error; err != nil {
		return fmt.Errorf("failed to soft-delete project environments: %w", err)
	}
	// Disable every dynamic-secret config scoped to the project (#369): a
	// disabled project must not go on minting live database credentials.
	// IssueLease/RenewLease refuse against a Disabled config; the caller
	// (core.DeleteProject) revokes the configs' outstanding active leases
	// against their real targets AFTER this transaction commits — that's
	// network I/O to arbitrary external systems and must not hold this DB
	// transaction open. Unlike secrets/environments, Disabled is a plain
	// boolean with no cascade timestamp: RestoreProject deliberately does
	// NOT clear it (see the Disabled field doc on DynamicSecretConfig).
	if err := tx.Model(&models.DynamicSecretConfig{}).
		Where("project_id = ? AND disabled = ?", id, false).Update("disabled", true).Error; err != nil {
		return fmt.Errorf("failed to disable project dynamic-secret configs: %w", err)
	}
	// Soft-delete the project itself with the same timestamp.
	result := tx.Model(&models.Project{}).
		Where(sqlWhereID, id).Update("deleted_at", deletedAt)
	if result.Error != nil {
		return fmt.Errorf("failed to delete project: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("project not found")
	}
	return nil
}

func (ls *LocalStorage) DeleteProject(ctx context.Context, id uint) error {
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		return deleteProjectCascade(tx, id)
	})
}

// DeleteProjectIfEmpty is the atomic form of DeleteProject(force=false)'s guard+cascade
// pair (#528 — see the storage.Storage interface doc comment on this method for why).
// Counts the project's live secrets and, only if zero, runs the exact same cascade
// DeleteProject does — all inside ONE transaction, so the count the guard rejects on
// is read from, and committed alongside, the same transaction as the delete (mirrors
// #313's original guarantee, just via a single storage-layer call instead of a
// core-layer WithTransaction wrapper).
func (ls *LocalStorage) DeleteProjectIfEmpty(ctx context.Context, id uint) (int, error) {
	var blockingSecretCount int
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var secretCount int64
		if err := tx.Model(&models.SecretNode{}).
			Where(sqlWhereProjectID, id).Count(&secretCount).Error; err != nil {
			return fmt.Errorf("failed to count project secrets: %w", err)
		}
		if secretCount > 0 {
			blockingSecretCount = int(secretCount)
			return nil
		}
		return deleteProjectCascade(tx, id)
	})
	if err != nil {
		return 0, err
	}
	return blockingSecretCount, nil
}

// RestoreProject reverses a project soft-delete: it clears deleted_at on the project
// and on ONLY the environments and secrets that were soft-deleted by the same
// DeleteProject cascade (matched by the uniform deletion timestamp). Secrets or
// environments a user had retired independently earlier carry a different deleted_at
// and are deliberately left in the recycle bin — restoring the project must not
// silently resurrect a deliberately-deleted secret (and re-grant its retained shares).
//
// Returns the number of environments and secrets the cascade actually brought back, so
// the caller can emit a per-type-count audit entry alongside the single project.restored
// event (#311) — otherwise a DR-test or accidental delete-then-undo of a whole project
// resurrects an unknown number of children with no forensic record of what came back.
func (ls *LocalStorage) RestoreProject(ctx context.Context, id uint) (restoredEnvironments, restoredSecrets int, err error) {
	txErr := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Read the cascade's deletion timestamp before clearing it.
		var project models.Project
		if err := tx.Unscoped().Where("id = ? AND deleted_at IS NOT NULL", id).First(&project).Error; err != nil {
			return fmt.Errorf("project not found or not deleted")
		}
		cascadeTS := project.DeletedAt.Time

		// Restore only the children whose deleted_at is at or after the cascade timestamp
		// (those removed by this DeleteProject); earlier, independently-retired rows are
		// strictly before it and stay deleted.
		envResult := tx.Unscoped().Model(&models.Environment{}).
			Where("project_id = ? AND deleted_at >= ?", id, cascadeTS).Update("deleted_at", nil)
		if envResult.Error != nil {
			return fmt.Errorf("failed to restore project environments: %w", envResult.Error)
		}
		restoredEnvironments = int(envResult.RowsAffected)

		secResult := tx.Unscoped().Model(&models.SecretNode{}).
			Where("project_id = ? AND deleted_at >= ?", id, cascadeTS).Update("deleted_at", nil)
		if secResult.Error != nil {
			return fmt.Errorf("failed to restore project secrets: %w", secResult.Error)
		}
		restoredSecrets = int(secResult.RowsAffected)

		// Clear the project last.
		if err := tx.Unscoped().Model(&models.Project{}).
			Where(sqlWhereID, id).Update("deleted_at", nil).Error; err != nil {
			return fmt.Errorf("failed to restore project: %w", err)
		}
		return nil
	})
	if txErr != nil {
		return 0, 0, txErr
	}
	return restoredEnvironments, restoredSecrets, nil
}

func (ls *LocalStorage) ListEnvironments(ctx context.Context) ([]*models.Environment, error) {
	var environments []*models.Environment
	return environments, ls.db.WithContext(ctx).Find(&environments).Error
}

func (ls *LocalStorage) ListEnvironmentsByProject(ctx context.Context, projectID uint) ([]*models.Environment, error) {
	var environments []*models.Environment
	return environments, ls.db.WithContext(ctx).Where(sqlWhereProjectID, projectID).
		Limit(maxEnvironmentListing).Find(&environments).Error
}

// ListEnvironmentsByProjectIncludingDeleted is like ListEnvironmentsByProject but
// also returns soft-deleted environments (DeletedAt populated), for the restore UI.
func (ls *LocalStorage) ListEnvironmentsByProjectIncludingDeleted(ctx context.Context, projectID uint) ([]*models.Environment, error) {
	var environments []*models.Environment
	return environments, ls.db.WithContext(ctx).Unscoped().Where(sqlWhereProjectID, projectID).
		Limit(maxEnvironmentListing).Find(&environments).Error
}

func (ls *LocalStorage) GetEnvironment(ctx context.Context, id uint) (*models.Environment, error) {
	var env models.Environment
	if err := ls.db.WithContext(ctx).First(&env, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("environment not found")
		}
		return nil, fmt.Errorf("failed to get environment: %w", err)
	}
	return &env, nil
}

func (ls *LocalStorage) DeleteEnvironment(ctx context.Context, id uint) error {
	// Block deletion if active secrets exist in this environment.
	var secretCount int64
	if err := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Where("environment_id = ? AND status = 'active'", id).
		Count(&secretCount).Error; err != nil {
		return fmt.Errorf("failed to count secrets in environment: %w", err)
	}
	if secretCount > 0 {
		return fmt.Errorf("environment has %d active secret(s); move or delete them before removing this environment", secretCount)
	}

	result := ls.db.WithContext(ctx).Delete(&models.Environment{}, id)
	if result.Error != nil {
		return fmt.Errorf("failed to delete environment: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("environment not found")
	}
	return nil
}

// RestoreEnvironment clears deleted_at on a soft-deleted environment, but refuses to
// restore one whose parent project is still soft-deleted — otherwise a holder of a
// still-extant project-scoped grant (a soft-deleted project does NOT revoke its role
// grants) could resurrect a usable, readable scope under a project an admin deleted to
// revoke access. Mirrors the parent-liveness guard on CreateProjectEnvironment.
func (ls *LocalStorage) RestoreEnvironment(ctx context.Context, projectID, id uint) error {
	if err := ls.requireLiveProject(ctx, projectID); err != nil {
		return err
	}
	result := ls.db.WithContext(ctx).Unscoped().Model(&models.Environment{}).
		Where("id = ? AND project_id = ? AND deleted_at IS NOT NULL", id, projectID).Update("deleted_at", nil)
	if result.Error != nil {
		return fmt.Errorf("failed to restore environment: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("environment not found or not deleted")
	}
	return nil
}

// --- Secrets ---

// CreateSecret creates a new secret in the database.
// CreateSecret ignores the optional plaintextValue variadic (#499): the value
// continues to flow through the existing, unchanged CreateSecretVersion path —
// this is a no-op parameter here, never read, never persisted. secret.ValueStored
// is deliberately left false (the zero value): the caller (core.CreateSecret)
// must still make its own CreateSecretVersion call for LocalStorage.
func (ls *LocalStorage) CreateSecret(ctx context.Context, secret *models.SecretNode, _ ...string) (*models.SecretNode, error) {
	if err := ls.db.WithContext(ctx).Create(secret).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return secret, nil
}

// GetSecret retrieves a secret by ID.
func (ls *LocalStorage) GetSecret(ctx context.Context, id uint) (*models.SecretNode, error) {
	var secret models.SecretNode
	if err := ls.db.WithContext(ctx).First(&secret, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &secret, nil
}

// GetSecretsByIDs batch-fetches secrets by ID in one query — the batch form of
// GetSecret. IDs with no matching (non-deleted) row are simply absent from the
// result, in whatever order GORM returns them (callers needing a specific order
// must sort/index by ID themselves). Used by the rotation planner's risk-scoring
// batch (#409) so scoring N candidate secrets costs one query, not N.
func (ls *LocalStorage) GetSecretsByIDs(ctx context.Context, ids []uint) ([]*models.SecretNode, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var secrets []*models.SecretNode
	if err := ls.db.WithContext(ctx).Where("id IN ?", ids).Find(&secrets).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return secrets, nil
}

// GetSecretByName retrieves a secret by name and scope.
func (ls *LocalStorage) GetSecretByName(ctx context.Context, name string, projectID, environmentID uint) (*models.SecretNode, error) {
	var secret models.SecretNode
	err := ls.db.WithContext(ctx).Where(
		"name = ? AND project_id = ? AND environment_id = ?",
		name, projectID, environmentID,
	).First(&secret).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &secret, nil
}

// ClearProjectSecretOwnership sets owner_id = 0 for every live secret in
// projectID owned by userID, removing the stale ownership tag left behind after
// a project member is offboarded (RBAC-002). A zero owner_id signals "no human
// owner" (the invariant enforced by secretOwnedBy), so CheckSecretPermission's
// owner short-circuit no longer fires for the removed user.
func (ls *LocalStorage) ClearProjectSecretOwnership(ctx context.Context, userID, projectID uint) error {
	err := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Where("owner_id = ? AND project_id = ? AND deleted_at IS NULL", userID, projectID).
		Update("owner_id", 0).Error
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// UpdateSecret updates an existing secret.
func (ls *LocalStorage) UpdateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error) {
	if err := ls.db.WithContext(ctx).Save(secret).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return secret, nil
}

// TransitionSecretStatus persists secret's full row via a conditional UPDATE
// gated on the row's CURRENT status still being fromStatus (see the interface
// doc in internal/core/storage/interface.go for why this exists alongside —
// not instead of — UpdateSecret). Mirrors TransitionMachineIdentityState's
// `WHERE id = ? AND state = ?` + `Select("*")` shape exactly, so every field
// the caller mutated on secret (Status, UpdatedAt, ...) is persisted in the
// same statement, not just a hardcoded column subset.
func (ls *LocalStorage) TransitionSecretStatus(ctx context.Context, secret *models.SecretNode, fromStatus string) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Where("id = ? AND status = ?", secret.ID, fromStatus).
		Select("*").
		Updates(secret)
	if res.Error != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	return res.RowsAffected == 1, nil
}

// SetSecretCertNotAfter caches a certificate-typed secret's parsed leaf expiry — a
// targeted single-column update that touches nothing else (ADR-056).
func (ls *LocalStorage) SetSecretCertNotAfter(ctx context.Context, secretID uint, notAfter *time.Time) error {
	if err := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Where(sqlWhereID, secretID).Update("cert_not_after", notAfter).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// SetRetentionOverride sets the per-secret retention override. days = 0 clears
// the override (reverts to the global policy). The caller is responsible for
// validating the minimum floor before invoking this method.
func (ls *LocalStorage) SetRetentionOverride(ctx context.Context, secretID uint, days int) error {
	if err := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Where(sqlWhereID, secretID).Update("retention_override_days", days).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// DeleteSecret deletes a secret by ID. #370: ShareRecord rows are a fully
// independent lifecycle from SecretNode's — left untouched, a share grant would
// silently reactivate (via CheckSharePermission) the instant the secret is later
// restored from the recycle bin, with zero re-authorization step, even when the
// secret was deleted specifically to sever a former grantee's access. "Delete
// means gone" for sharing too, so revoke every active share for this secret in
// the same transaction as the secret's own soft-delete.
func (ls *LocalStorage) DeleteSecret(ctx context.Context, id uint) error {
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Delete(&models.SecretNode{}, id)
		if result.Error != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
		}
		if err := tx.Where("secret_id = ? AND deleted_at IS NULL", id).
			Delete(&models.ShareRecord{}).Error; err != nil {
			return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
		}
		// CWE-284: revoke SecretACL grants in the same transaction so that
		// ACL-based access cannot silently reactivate on restore (same class of
		// bug fixed for ShareRecord in #370).
		if err := tx.Where("secret_id = ?", id).Delete(&models.SecretACL{}).Error; err != nil {
			return fmt.Errorf("failed to revoke secret ACLs: %w", err)
		}
		return nil
	})
}

// GetSecretIncludingDeleted loads a secret even when soft-deleted (Unscoped).
func (ls *LocalStorage) GetSecretIncludingDeleted(ctx context.Context, id uint) (*models.SecretNode, error) {
	var secret models.SecretNode
	if err := ls.db.WithContext(ctx).Unscoped().First(&secret, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	return &secret, nil
}

// RestoreSecret clears a soft-deleted secret's deleted_at (ADR-033). Uses Unscoped to
// reach the soft-deleted row, which GORM hides by default. It refuses to restore a
// secret whose parent project or environment is still soft-deleted — otherwise a holder
// of a still-extant project-scoped grant could resurrect a live, readable secret inside
// a project an admin deleted to revoke access (the project delete does not revoke role
// grants). To bring such a secret back, restore the parent project first (which
// cascade-restores its children).
func (ls *LocalStorage) RestoreSecret(ctx context.Context, id uint) error {
	var secret models.SecretNode
	if err := ls.db.WithContext(ctx).Unscoped().Select("id", "project_id", "environment_id").First(&secret, id).Error; err != nil {
		return fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
	}
	if err := ls.requireLiveProject(ctx, secret.ProjectID); err != nil {
		return err
	}
	if secret.EnvironmentID != 0 {
		if err := ls.requireLiveEnvironment(ctx, secret.EnvironmentID); err != nil {
			return err
		}
	}
	result := ls.db.WithContext(ctx).Unscoped().Model(&models.SecretNode{}).
		Where("id = ? AND deleted_at IS NOT NULL", id).Update("deleted_at", nil)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
	}
	return nil
}

// requireLiveProject returns an error when the project is missing or soft-deleted.
func (ls *LocalStorage) requireLiveProject(ctx context.Context, projectID uint) error {
	var n int64
	if err := ls.db.WithContext(ctx).Model(&models.Project{}).
		Where("id = ? AND deleted_at IS NULL", projectID).Count(&n).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if n == 0 {
		return fmt.Errorf("cannot restore: the parent project is deleted — restore the project first")
	}
	return nil
}

// requireLiveEnvironment returns an error when the environment is missing or soft-deleted.
func (ls *LocalStorage) requireLiveEnvironment(ctx context.Context, environmentID uint) error {
	var n int64
	if err := ls.db.WithContext(ctx).Model(&models.Environment{}).
		Where("id = ? AND deleted_at IS NULL", environmentID).Count(&n).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if n == 0 {
		return fmt.Errorf("cannot restore: the parent environment is deleted — restore the environment first")
	}
	return nil
}

// ListSecrets lists secrets with filtering and pagination.
// When project_id is provided, results are always scoped to that project via
// a JOIN through environments — prevents cross-project leakage if a caller
// passes a mismatched environment_id.
func (ls *LocalStorage) ListSecrets(ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) { // NOSONAR -- cognitive complexity 16, suppress go:S3776
	query := ls.db.WithContext(ctx).Model(&models.SecretNode{})
	if filter.DeletedOnly {
		// Recycle bin: only soft-deleted rows, newest-deleted first (ordered in SQL
		// so it survives the LIMIT). Unscoped reaches past GORM's deleted_at IS NULL
		// scope; the explicit predicate then keeps just the trashed secrets.
		query = query.Unscoped().
			Where("secret_nodes.deleted_at IS NOT NULL").
			Order("secret_nodes.deleted_at DESC")
	} else if filter.IncludeDeleted {
		// Reach soft-deleted rows too (restore UI); GORM hides them by default.
		query = query.Unscoped()
	}

	if filter.ProjectID != nil {
		// JOIN ensures environment_id is always verified against the project,
		// preventing cross-project leakage.
		query = query.Joins("JOIN environments ON environments.id = secret_nodes.environment_id").
			Where("secret_nodes.project_id = ?", *filter.ProjectID).
			Where("environments.project_id = ?", *filter.ProjectID)
	}
	if filter.EnvironmentID != nil {
		query = query.Where("secret_nodes.environment_id = ?", *filter.EnvironmentID)
	}
	if filter.Type != nil {
		query = query.Where("secret_nodes.type = ?", *filter.Type)
	}
	if filter.CreatedBy != nil {
		query = query.Where("secret_nodes.created_by = ?", *filter.CreatedBy)
	}
	if filter.OwnerID != nil {
		query = query.Where("secret_nodes.owner_id = ?", *filter.OwnerID)
	}
	if filter.ExpiresBefore != nil {
		query = query.Where("secret_nodes.expiration IS NOT NULL AND secret_nodes.expiration < ?", *filter.ExpiresBefore)
		// #G24: order soonest-expiring first so a capped PageSize returns the
		// TRUE most-urgent rows, not an arbitrary unordered slice truncated to
		// whatever page happened to be returned — callers filtering by expiry
		// (ListExpiringSecrets) need the returned page to be exactly "the N
		// secrets closest to expiring", not "N secrets that happen to expire
		// before the cutoff" in no particular order.
		query = query.Order("secret_nodes.expiration ASC")
	}
	if filter.Classification != nil {
		if *filter.Classification == "unclassified" {
			query = query.Where("secret_nodes.classification = '' OR secret_nodes.classification IS NULL")
		} else {
			query = query.Where("secret_nodes.classification = ?", *filter.Classification)
		}
	}
	if filter.CreatedAfter != nil {
		query = query.Where("secret_nodes.created_at > ?", *filter.CreatedAfter)
	}
	if filter.CreatedBefore != nil {
		query = query.Where("secret_nodes.created_at < ?", *filter.CreatedBefore)
	}
	if filter.IsSecret != nil {
		query = query.Where("secret_nodes.is_secret = ?", *filter.IsSecret)
	}
	if filter.ParentID != nil {
		query = query.Where("secret_nodes.parent_id = ?", *filter.ParentID)
	}
	if filter.FolderOnly {
		query = query.Where("secret_nodes.is_secret = ?", false)
	}
	if filter.Search != nil && *filter.Search != "" {
		// escapeLIKE sanitises % and _ so a caller-supplied search term cannot
		// widen the match beyond the intended prefix/suffix anchors (#r124 LIKE injection).
		query = query.Where(`LOWER(secret_nodes.name) LIKE LOWER(?) ESCAPE '\'`, "%"+escapeLIKE(*filter.Search)+"%")
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	pageSize := clampPageSize(filter.PageSize)
	page := clampPage(filter.Page)
	offset := (page - 1) * pageSize
	query = query.Offset(offset).Limit(pageSize)

	var secrets []*models.SecretNode
	if err := query.Find(&secrets).Error; err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return secrets, total, nil
}

// ListOrphanedSecrets returns the project's live secrets whose owner is no longer a
// live user (deleted or soft-deleted) — offboarding hygiene. The environment JOIN
// scopes to the project (anti-leak, consistent with ListSecrets); the LEFT JOIN to a
// non-soft-deleted user with no match (users.id IS NULL) is the "owner gone" test.
// GORM auto-applies secret_nodes.deleted_at IS NULL, so only live secrets are listed.
func (ls *LocalStorage) ListOrphanedSecrets(ctx context.Context, projectID uint) ([]*models.SecretNode, error) {
	var secrets []*models.SecretNode
	err := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Joins("JOIN environments ON environments.id = secret_nodes.environment_id AND environments.project_id = ?", projectID).
		Joins("LEFT JOIN users ON users.id = secret_nodes.owner_id AND users.deleted_at IS NULL").
		Where("secret_nodes.project_id = ?", projectID).
		Where("users.id IS NULL").
		Order("secret_nodes.name ASC").
		Limit(maxUnboundedListRows).
		Find(&secrets).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return secrets, nil
}

// CountOrphanedSecretsByProject returns the same "owner no longer live" count as
// ListOrphanedSecrets, for every project in projectIDs, via a single
// `GROUP BY secret_nodes.project_id` query — the deployment-wide counterpart used
// by the hygiene rollup (#393) instead of calling ListOrphanedSecrets once per
// project (which turned "every project" into a per-project round trip). A project
// with no orphaned secrets is simply absent from the returned map.
func (ls *LocalStorage) CountOrphanedSecretsByProject(ctx context.Context, projectIDs []uint) (map[uint]int, error) {
	counts := make(map[uint]int)
	if len(projectIDs) == 0 {
		return counts, nil
	}
	type row struct {
		ProjectID uint
		N         int64
	}
	var rows []row
	err := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Select("secret_nodes.project_id AS project_id, COUNT(*) AS n").
		Joins("JOIN environments ON environments.id = secret_nodes.environment_id AND environments.project_id = secret_nodes.project_id").
		Joins("LEFT JOIN users ON users.id = secret_nodes.owner_id AND users.deleted_at IS NULL").
		Where("secret_nodes.project_id IN ?", projectIDs).
		Where("users.id IS NULL").
		Group("secret_nodes.project_id").
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, r := range rows {
		counts[r.ProjectID] = int(r.N)
	}
	return counts, nil
}

// CountExpiringSecretsByProject returns, for every project in projectIDs, the
// count of live secrets with a non-null expiration before expiresBefore — the
// same definition ListSecrets(ExpiresBefore) uses per-project, but grouped into a
// single deployment-wide query for the hygiene rollup (#393). A project with no
// expiring secrets is simply absent from the returned map.
func (ls *LocalStorage) CountExpiringSecretsByProject(ctx context.Context, projectIDs []uint, expiresBefore time.Time) (map[uint]int, error) {
	counts := make(map[uint]int)
	if len(projectIDs) == 0 {
		return counts, nil
	}
	type row struct {
		ProjectID uint
		N         int64
	}
	var rows []row
	err := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Select("project_id, COUNT(*) AS n").
		Where("project_id IN ?", projectIDs).
		Where("expiration IS NOT NULL AND expiration < ?", expiresBefore).
		Group("project_id").
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, r := range rows {
		counts[r.ProjectID] = int(r.N)
	}
	return counts, nil
}

// ListLiveSecretNamesByProject returns every live secret (folders excluded) across
// every project in projectIDs — id/name/type/classification/environment plus its
// project ID — in a SINGLE query ordered by project then name, instead of one
// ListSecrets call per project (#416, the deployment-wide name-conformance scan's
// N+1 fix). Fetches one row beyond limit so truncation can be reported without a
// separate COUNT query.
func (ls *LocalStorage) ListLiveSecretNamesByProject(ctx context.Context, projectIDs []uint, limit int) ([]storage.SecretNameRow, bool, error) {
	if len(projectIDs) == 0 {
		return nil, false, nil
	}
	var rows []storage.SecretNameRow
	err := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Select("project_id, id, name, type, classification, environment_id").
		Where("project_id IN ?", projectIDs).
		Where("is_secret = ?", true).
		Order("project_id ASC, name ASC").
		Limit(limit + 1).
		Scan(&rows).Error
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	truncated := false
	if len(rows) > limit {
		truncated = true
		rows = rows[:limit]
	}
	return rows, truncated, nil
}

// GetSecretTags returns the secret's tag names, sorted.
func (ls *LocalStorage) GetSecretTags(ctx context.Context, secretID uint) ([]string, error) {
	var names []string
	err := ls.db.WithContext(ctx).
		Model(&models.Tag{}).
		Joins("JOIN secret_tags ON secret_tags.tag_id = tags.id").
		Where("secret_tags.secret_node_id = ?", secretID).
		Order("tags.name ASC").
		Pluck("tags.name", &names).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return names, nil
}

// SetSecretTags replaces the secret's tag associations with exactly tagNames,
// upserting any new Tag rows by name. Runs in a transaction so the secret never
// observes a partial tag set.
func (ls *LocalStorage) SetSecretTags(ctx context.Context, secretID uint, tagNames []string) error {
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where(sqlWhereSecretNodeID, secretID).Delete(&models.SecretTag{}).Error; err != nil {
			return fmt.Errorf("clear tags: %w", err)
		}
		for _, name := range tagNames {
			var tag models.Tag
			if err := tx.Where(models.Tag{Name: name}).FirstOrCreate(&tag).Error; err != nil {
				return fmt.Errorf("upsert tag %q: %w", name, err)
			}
			if err := tx.Create(&models.SecretTag{SecretNodeID: secretID, TagID: tag.ID}).Error; err != nil {
				return fmt.Errorf("link tag %q: %w", name, err)
			}
		}
		return nil
	})
}

// --- Versions ---

// CreateSecretVersion creates a new version of a secret.
func (ls *LocalStorage) CreateSecretVersion(ctx context.Context, version *models.SecretVersion) (*models.SecretVersion, error) {
	if err := ls.db.WithContext(ctx).Create(version).Error; err != nil {
		if isUniqueViolation(err) {
			// The unique index on (secret_node_id, version_number) (#121) caught a
			// concurrent rotation that already claimed this version number. Translate to
			// the sentinel so RotateSecret can retry with a freshly re-read latest version
			// instead of failing the rotation outright on ordinary contention.
			return nil, fmt.Errorf("%w: %v", storage.ErrDuplicateSecretVersion, err)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return version, nil
}

// GetSecretVersions retrieves all versions of a secret ordered newest-first.
func (ls *LocalStorage) GetSecretVersions(ctx context.Context, secretID uint) ([]*models.SecretVersion, error) {
	var versions []*models.SecretVersion
	if err := ls.db.WithContext(ctx).Where(sqlWhereSecretNodeID, secretID).Order("version_number DESC").Find(&versions).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return versions, nil
}

// GetLatestSecretVersion retrieves the most recent version of a secret.
func (ls *LocalStorage) GetLatestSecretVersion(ctx context.Context, secretID uint) (*models.SecretVersion, error) {
	var version models.SecretVersion
	if err := ls.db.WithContext(ctx).Where(sqlWhereSecretNodeID, secretID).Order("version_number DESC").First(&version).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s", i18n.T("ErrorVersionNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &version, nil
}

// IncrementSecretReadCount atomically increments the read counter for a secret version.
func (ls *LocalStorage) IncrementSecretReadCount(ctx context.Context, versionID uint) error {
	if err := ls.db.WithContext(ctx).Model(&models.SecretVersion{}).
		Where(sqlWhereID, versionID).
		UpdateColumn("read_count", gorm.Expr(sqlIncrReadCount)).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// TryIncrementSecretReadCount atomically increments read_count only while it is
// still below maxReads. The conditional WHERE makes check-and-increment a single
// row-level-serialized UPDATE, so concurrent reads of a max-reads secret can never
// collectively exceed the cap. RowsAffected==1 means this read is within the cap.
func (ls *LocalStorage) TryIncrementSecretReadCount(ctx context.Context, versionID uint, maxReads int) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.SecretVersion{}).
		Where("id = ? AND read_count < ?", versionID, maxReads).
		UpdateColumn("read_count", gorm.Expr(sqlIncrReadCount))
	if res.Error != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	return res.RowsAffected == 1, nil
}

// TryIncrementSecretNodeReadCount is TryIncrementSecretReadCount's secret-level
// twin (#133): the same atomic conditional-UPDATE pattern, keyed on the secret
// (secret_nodes.read_count) instead of a version, so the cap survives rotate/
// rollback creating a new version.
func (ls *LocalStorage) TryIncrementSecretNodeReadCount(ctx context.Context, secretID uint, maxReads int) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.SecretNode{}).
		Where("id = ? AND read_count < ?", secretID, maxReads).
		UpdateColumn("read_count", gorm.Expr(sqlIncrReadCount))
	if res.Error != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	return res.RowsAffected == 1, nil
}

// maxAncestorDepth caps the ParentID chain walk to prevent infinite loops
// from accidental circular references in secret_nodes.parent_id.
const maxAncestorDepth = 20

// GetSecretAncestors walks the ParentID chain for nodeID and returns the
// ancestor IDs ordered from immediate parent to root. Capped at
// maxAncestorDepth levels. Stopping early (cycle / depth limit) never
// returns an error — missing ancestors are simply absent, the caller walks
// as far as the chain allows.
func (ls *LocalStorage) GetSecretAncestors(ctx context.Context, nodeID uint) ([]uint, error) {
	var ancestors []uint
	visited := make(map[uint]struct{})
	currentID := nodeID
	for range maxAncestorDepth {
		var node models.SecretNode
		err := ls.db.WithContext(ctx).
			Select("id", "parent_id").
			First(&node, currentID).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			break // node not found — stop walk
		}
		if err != nil {
			return nil, fmt.Errorf("get secret ancestors (node %d): %w", currentID, err)
		}
		if node.ParentID == nil {
			break // reached the root
		}
		parentID := *node.ParentID
		if _, seen := visited[parentID]; seen {
			break // cycle guard
		}
		visited[parentID] = struct{}{}
		ancestors = append(ancestors, parentID)
		currentID = parentID
	}
	return ancestors, nil
}

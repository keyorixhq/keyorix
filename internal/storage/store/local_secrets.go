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
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// --- Project / Environment ---

func (ls *LocalStorage) CreateProject(ctx context.Context, project *models.Project) (*models.Project, error) {
	return project, ls.db.WithContext(ctx).Create(project).Error
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
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("project not found")
		}
		return nil, fmt.Errorf("failed to get project: %w", err)
	}
	return &project, nil
}

func (ls *LocalStorage) UpdateProject(ctx context.Context, project *models.Project) (*models.Project, error) {
	if err := ls.db.WithContext(ctx).Save(project).Error; err != nil {
		return nil, fmt.Errorf("failed to update project: %w", err)
	}
	return project, nil
}

func (ls *LocalStorage) DeleteProject(ctx context.Context, id uint) error {
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Soft-delete all secrets in the project
		if err := tx.Where("project_id = ?", id).Delete(&models.SecretNode{}).Error; err != nil {
			return fmt.Errorf("failed to soft-delete project secrets: %w", err)
		}
		// Soft-delete all environments in the project
		if err := tx.Where("project_id = ?", id).Delete(&models.Environment{}).Error; err != nil {
			return fmt.Errorf("failed to soft-delete project environments: %w", err)
		}
		// Soft-delete the project itself
		result := tx.Delete(&models.Project{}, id)
		if result.Error != nil {
			return fmt.Errorf("failed to delete project: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("project not found")
		}
		return nil
	})
}

// RestoreProject reverses a project soft-delete: it clears deleted_at on the
// project and on the environments that were soft-deleted with it. Secrets are
// NOT restored — DeleteProject hard-deletes secret rows (SecretNode has no
// soft-delete column; per-secret soft delete is a separate, ADR-gated M2 item),
// so a restored project comes back with its environment structure but no secrets.
func (ls *LocalStorage) RestoreProject(ctx context.Context, id uint) error {
	return ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		result := tx.Unscoped().Model(&models.Project{}).
			Where("id = ? AND deleted_at IS NOT NULL", id).Update("deleted_at", nil)
		if result.Error != nil {
			return fmt.Errorf("failed to restore project: %w", result.Error)
		}
		if result.RowsAffected == 0 {
			return fmt.Errorf("project not found or not deleted")
		}
		if err := tx.Unscoped().Model(&models.Environment{}).
			Where("project_id = ?", id).Update("deleted_at", nil).Error; err != nil {
			return fmt.Errorf("failed to restore project environments: %w", err)
		}
		// Secrets cascade-restore too (ADR-033 made them soft-deletable; the
		// DeleteProject cascade soft-deletes them, so a restore must bring them back).
		if err := tx.Unscoped().Model(&models.SecretNode{}).
			Where("project_id = ?", id).Update("deleted_at", nil).Error; err != nil {
			return fmt.Errorf("failed to restore project secrets: %w", err)
		}
		return nil
	})
}

func (ls *LocalStorage) ListEnvironments(ctx context.Context) ([]*models.Environment, error) {
	var environments []*models.Environment
	return environments, ls.db.WithContext(ctx).Find(&environments).Error
}

func (ls *LocalStorage) ListEnvironmentsByProject(ctx context.Context, projectID uint) ([]*models.Environment, error) {
	var environments []*models.Environment
	return environments, ls.db.WithContext(ctx).Where("project_id = ?", projectID).Find(&environments).Error
}

// ListEnvironmentsByProjectIncludingDeleted is like ListEnvironmentsByProject but
// also returns soft-deleted environments (DeletedAt populated), for the restore UI.
func (ls *LocalStorage) ListEnvironmentsByProjectIncludingDeleted(ctx context.Context, projectID uint) ([]*models.Environment, error) {
	var environments []*models.Environment
	return environments, ls.db.WithContext(ctx).Unscoped().Where("project_id = ?", projectID).Find(&environments).Error
}

func (ls *LocalStorage) GetEnvironment(ctx context.Context, id uint) (*models.Environment, error) {
	var env models.Environment
	if err := ls.db.WithContext(ctx).First(&env, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
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

// RestoreEnvironment clears deleted_at on a soft-deleted environment.
func (ls *LocalStorage) RestoreEnvironment(ctx context.Context, projectID, id uint) error {
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
func (ls *LocalStorage) CreateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error) {
	if err := ls.db.WithContext(ctx).Create(secret).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return secret, nil
}

// GetSecret retrieves a secret by ID.
func (ls *LocalStorage) GetSecret(ctx context.Context, id uint) (*models.SecretNode, error) {
	var secret models.SecretNode
	if err := ls.db.WithContext(ctx).First(&secret, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &secret, nil
}

// GetSecretByName retrieves a secret by name and scope.
func (ls *LocalStorage) GetSecretByName(ctx context.Context, name string, projectID, environmentID uint) (*models.SecretNode, error) {
	var secret models.SecretNode
	err := ls.db.WithContext(ctx).Where(
		"name = ? AND project_id = ? AND environment_id = ?",
		name, projectID, environmentID,
	).First(&secret).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &secret, nil
}

// UpdateSecret updates an existing secret.
func (ls *LocalStorage) UpdateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error) {
	if err := ls.db.WithContext(ctx).Save(secret).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return secret, nil
}

// DeleteSecret deletes a secret by ID.
func (ls *LocalStorage) DeleteSecret(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Delete(&models.SecretNode{}, id)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
	}
	return nil
}

// GetSecretIncludingDeleted loads a secret even when soft-deleted (Unscoped).
func (ls *LocalStorage) GetSecretIncludingDeleted(ctx context.Context, id uint) (*models.SecretNode, error) {
	var secret models.SecretNode
	if err := ls.db.WithContext(ctx).Unscoped().First(&secret, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}
	return &secret, nil
}

// RestoreSecret clears a soft-deleted secret's deleted_at (ADR-033). Uses
// Unscoped to reach the soft-deleted row, which GORM hides by default.
func (ls *LocalStorage) RestoreSecret(ctx context.Context, id uint) error {
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

// ListSecrets lists secrets with filtering and pagination.
// When project_id is provided, results are always scoped to that project via
// a JOIN through environments — prevents cross-project leakage if a caller
// passes a mismatched environment_id.
func (ls *LocalStorage) ListSecrets(ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
	query := ls.db.WithContext(ctx).Model(&models.SecretNode{})
	if filter.IncludeDeleted {
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
	if filter.CreatedAfter != nil {
		query = query.Where("secret_nodes.created_at > ?", *filter.CreatedAfter)
	}
	if filter.CreatedBefore != nil {
		query = query.Where("secret_nodes.created_at < ?", *filter.CreatedBefore)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	offset := (filter.Page - 1) * filter.PageSize
	query = query.Offset(offset).Limit(filter.PageSize)

	var secrets []*models.SecretNode
	if err := query.Find(&secrets).Error; err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return secrets, total, nil
}

// --- Versions ---

// CreateSecretVersion creates a new version of a secret.
func (ls *LocalStorage) CreateSecretVersion(ctx context.Context, version *models.SecretVersion) (*models.SecretVersion, error) {
	if err := ls.db.WithContext(ctx).Create(version).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return version, nil
}

// GetSecretVersions retrieves all versions of a secret ordered newest-first.
func (ls *LocalStorage) GetSecretVersions(ctx context.Context, secretID uint) ([]*models.SecretVersion, error) {
	var versions []*models.SecretVersion
	if err := ls.db.WithContext(ctx).Where("secret_node_id = ?", secretID).Order("version_number DESC").Find(&versions).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return versions, nil
}

// GetLatestSecretVersion retrieves the most recent version of a secret.
func (ls *LocalStorage) GetLatestSecretVersion(ctx context.Context, secretID uint) (*models.SecretVersion, error) {
	var version models.SecretVersion
	if err := ls.db.WithContext(ctx).Where("secret_node_id = ?", secretID).Order("version_number DESC").First(&version).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("%s", i18n.T("ErrorVersionNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &version, nil
}

// IncrementSecretReadCount atomically increments the read counter for a secret version.
func (ls *LocalStorage) IncrementSecretReadCount(ctx context.Context, versionID uint) error {
	if err := ls.db.WithContext(ctx).Model(&models.SecretVersion{}).
		Where("id = ?", versionID).
		UpdateColumn("read_count", gorm.Expr("read_count + 1")).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

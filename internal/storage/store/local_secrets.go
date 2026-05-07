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

func (ls *LocalStorage) ListEnvironments(ctx context.Context) ([]*models.Environment, error) {
	var environments []*models.Environment
	return environments, ls.db.WithContext(ctx).Find(&environments).Error
}

func (ls *LocalStorage) ListEnvironmentsByProject(ctx context.Context, projectID uint) ([]*models.Environment, error) {
	var environments []*models.Environment
	return environments, ls.db.WithContext(ctx).Where("project_id = ?", projectID).Find(&environments).Error
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

// ListSecrets lists secrets with filtering and pagination.
// When project_id is provided, results are always scoped to that project via
// a JOIN through environments — prevents cross-project leakage if a caller
// passes a mismatched environment_id.
func (ls *LocalStorage) ListSecrets(ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
	query := ls.db.WithContext(ctx).Model(&models.SecretNode{})

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

// local_secret_dependencies.go — secret dependency-graph edge persistence (ADR-052).
// Each row is a directed edge "dependent depends on depends_on" within one project;
// the core layer builds the graph from a project's edges for impact analysis and
// rotation ordering. For the remote equivalent see remote_secret_dependencies.go.
package store

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) CreateSecretDependency(ctx context.Context, d *models.SecretDependency) (*models.SecretDependency, error) {
	if err := ls.db.WithContext(ctx).Create(d).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return d, nil
}

func (ls *LocalStorage) GetSecretDependency(ctx context.Context, id uint) (*models.SecretDependency, error) {
	var d models.SecretDependency
	if err := ls.db.WithContext(ctx).First(&d, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &d, nil
}

func (ls *LocalStorage) ListSecretDependenciesForProject(ctx context.Context, projectID uint) ([]*models.SecretDependency, error) {
	var rows []*models.SecretDependency
	if err := ls.db.WithContext(ctx).Where("project_id = ?", projectID).Order("id ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) DeleteSecretDependency(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Delete(&models.SecretDependency{}, id)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}

// local_machine_identities.go — machine identity persistence (ADR-023).
//
// For the remote (HTTP) equivalent see remote_machine_identities.go.
package store

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) CreateMachineIdentity(ctx context.Context, m *models.MachineIdentity) (*models.MachineIdentity, error) {
	if err := ls.db.WithContext(ctx).Create(m).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return m, nil
}

func (ls *LocalStorage) GetMachineIdentity(ctx context.Context, id uint) (*models.MachineIdentity, error) {
	var m models.MachineIdentity
	if err := ls.db.WithContext(ctx).First(&m, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &m, nil
}

func (ls *LocalStorage) UpdateMachineIdentity(ctx context.Context, m *models.MachineIdentity) error {
	if err := ls.db.WithContext(ctx).Save(m).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

func (ls *LocalStorage) ListMachineIdentities(ctx context.Context, projectID uint) ([]*models.MachineIdentity, error) {
	var rows []*models.MachineIdentity
	err := ls.db.WithContext(ctx).
		Where("project_id = ?", projectID).
		Order("created_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) CountMachineIdentitiesByClassification(ctx context.Context) (map[string]int, error) {
	return countByClassification(ctx, ls.db, &models.MachineIdentity{})
}

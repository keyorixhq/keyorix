// local_connector_project_bindings.go — persistence for Connect connector→project
// ID bindings (ADR-082 branch 2). See models.ConnectorProjectBinding's own doc
// comment for why boot-time resolution is pinned by ID and never re-resolved by name
// on a later boot. This file only stores and reads the binding rows; the
// resolve-or-create decision and the rename/deleted-project detection live in
// server/main.go's boot-time wiring.
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// GetConnectorProjectBinding returns the persisted binding for connector, or a
// "not found"-substring error if none exists yet (first boot for that connector).
func (ls *LocalStorage) GetConnectorProjectBinding(ctx context.Context, connector string) (*models.ConnectorProjectBinding, error) {
	var binding models.ConnectorProjectBinding
	if err := ls.db.WithContext(ctx).Where("connector = ?", connector).First(&binding).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("connector project binding not found")
		}
		return nil, fmt.Errorf("failed to get connector project binding: %w", err)
	}
	return &binding, nil
}

// CreateConnectorProjectBinding persists a connector's first-boot project
// resolution. The unique index on Connector makes re-creating a binding for an
// already-bound connector a conflict — callers must check
// GetConnectorProjectBinding first, exactly like the boot-time resolution logic
// does.
func (ls *LocalStorage) CreateConnectorProjectBinding(ctx context.Context, binding *models.ConnectorProjectBinding) (*models.ConnectorProjectBinding, error) {
	if err := ls.db.WithContext(ctx).Create(binding).Error; err != nil {
		return nil, fmt.Errorf("failed to create connector project binding: %w", err)
	}
	return binding, nil
}

// ListConnectorProjectBindings returns every persisted binding row, unfiltered
// (#1477's orphan-detection direction — see the boot-time consistency warning
// in server/main.go, the only caller).
func (ls *LocalStorage) ListConnectorProjectBindings(ctx context.Context) ([]*models.ConnectorProjectBinding, error) {
	var bindings []*models.ConnectorProjectBinding
	if err := ls.db.WithContext(ctx).Find(&bindings).Error; err != nil {
		return nil, fmt.Errorf("failed to list connector project bindings: %w", err)
	}
	return bindings, nil
}

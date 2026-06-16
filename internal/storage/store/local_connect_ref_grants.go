// local_connect_ref_grants.go — persistence for Keyorix Connect per-reference RBAC
// grants (ADR-045). A grant scopes which secret references a role may read through a
// given connector; enforcement (deny-by-default once a connector has any grant) lives
// in the core layer. This file only stores and reads the grant rows.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListConnectRefGrantsByConnector returns the grants scoped to one connector — the
// hot path consulted on every federated read.
func (ls *LocalStorage) ListConnectRefGrantsByConnector(ctx context.Context, connector string) ([]*models.ConnectRefGrant, error) {
	var grants []*models.ConnectRefGrant
	if err := ls.db.WithContext(ctx).
		Where("connector = ?", connector).
		Find(&grants).Error; err != nil {
		return nil, err
	}
	return grants, nil
}

// ListConnectRefGrants returns every grant (management/listing), ordered by connector
// then role for a stable display.
func (ls *LocalStorage) ListConnectRefGrants(ctx context.Context) ([]*models.ConnectRefGrant, error) {
	var grants []*models.ConnectRefGrant
	if err := ls.db.WithContext(ctx).
		Order("connector asc, role_id asc, ref_prefix asc").
		Find(&grants).Error; err != nil {
		return nil, err
	}
	return grants, nil
}

// CreateConnectRefGrant persists a grant. The (role_id, connector, ref_prefix) unique
// index makes re-creating an identical grant a conflict; callers should treat that as
// idempotent at the API layer.
func (ls *LocalStorage) CreateConnectRefGrant(ctx context.Context, grant *models.ConnectRefGrant) (*models.ConnectRefGrant, error) {
	if err := ls.db.WithContext(ctx).Create(grant).Error; err != nil {
		return nil, err
	}
	return grant, nil
}

// DeleteConnectRefGrant removes a grant by id (no-op if it does not exist).
func (ls *LocalStorage) DeleteConnectRefGrant(ctx context.Context, id uint) error {
	return ls.db.WithContext(ctx).Delete(&models.ConnectRefGrant{}, id).Error
}

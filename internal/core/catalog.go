package core

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListNamespaces returns all namespaces from storage.
func (c *KeyorixCore) ListNamespaces(ctx context.Context) ([]*models.Namespace, error) {
	return c.storage.ListNamespaces(ctx)
}

// ListZones returns all zones from storage.
func (c *KeyorixCore) ListZones(ctx context.Context) ([]*models.Zone, error) {
	return c.storage.ListZones(ctx)
}

// ListEnvironments returns all environments from storage.
func (c *KeyorixCore) ListEnvironments(ctx context.Context) ([]*models.Environment, error) {
	return c.storage.ListEnvironments(ctx)
}

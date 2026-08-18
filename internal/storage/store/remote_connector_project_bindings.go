// remote_connector_project_bindings.go — RemoteStorage passthrough for Connect
// connector→project ID bindings (ADR-082 branch 2). A downstream Keyorix server
// booted with storage.type: remote (ADR-049) proxies these to whichever upstream
// server it's configured against, through routes registered in
// server/http/router.go under /api/v1/system/connector-project-bindings (gated on
// the existing system.write RBAC permission — the same credential a RemoteStorage
// client already needs for every other proxied call, so this introduces no new
// privilege class). This is a real, DB-backed implementation, not a stub: backlog
// #527 already documented the failure shape a "not supported in remote storage"
// stub produces here — the calling boot-time resolution logic (server/main.go)
// would treat the resulting error as an unresolvable connector and fail boot on
// every connector, on every storage.type: remote node with Connect configured.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// connectorProjectBindingWire mirrors models.ConnectorProjectBinding's fields
// exactly (snake_case) — the wire shape the proxy handler
// (server/http/handlers/connector_project_bindings_proxy.go) sends/expects.
type connectorProjectBindingWire struct {
	ID          uint      `json:"id"`
	Connector   string    `json:"connector"`
	ProjectID   uint      `json:"project_id"`
	ProjectName string    `json:"project_name"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func newConnectorProjectBindingWire(b *models.ConnectorProjectBinding) connectorProjectBindingWire {
	return connectorProjectBindingWire{
		ID:          b.ID,
		Connector:   b.Connector,
		ProjectID:   b.ProjectID,
		ProjectName: b.ProjectName,
		CreatedAt:   b.CreatedAt,
		UpdatedAt:   b.UpdatedAt,
	}
}

func (w connectorProjectBindingWire) toModel() *models.ConnectorProjectBinding {
	return &models.ConnectorProjectBinding{
		ID:          w.ID,
		Connector:   w.Connector,
		ProjectID:   w.ProjectID,
		ProjectName: w.ProjectName,
		CreatedAt:   w.CreatedAt,
		UpdatedAt:   w.UpdatedAt,
	}
}

// GetConnectorProjectBinding retrieves a connector's binding via GET
// /api/v1/system/connector-project-bindings/{connector}.
func (rs *RemoteStorage) GetConnectorProjectBinding(ctx context.Context, connector string) (*models.ConnectorProjectBinding, error) {
	path := "/api/v1/system/connector-project-bindings/" + url.PathEscape(connector)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get connector project binding: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get connector project binding failed: %s", resp.Error.Error())
	}
	var wire connectorProjectBindingWire
	if err := json.Unmarshal(resp.Data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

// CreateConnectorProjectBinding persists a connector's first-boot project
// resolution via POST /api/v1/system/connector-project-bindings.
func (rs *RemoteStorage) CreateConnectorProjectBinding(ctx context.Context, binding *models.ConnectorProjectBinding) (*models.ConnectorProjectBinding, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/connector-project-bindings", newConnectorProjectBindingWire(binding))
	if err != nil {
		return nil, fmt.Errorf("failed to create connector project binding: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create connector project binding failed: %s", resp.Error.Error())
	}
	var wire connectorProjectBindingWire
	if err := json.Unmarshal(resp.Data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

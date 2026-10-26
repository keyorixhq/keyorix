package storage

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ConnectorStore is the Storage slice for connect-ref grants and connector project bindings.
// Storage (interface.go) embeds it; the method set of Storage is the union of
// the per-domain interfaces, so callers and implementers are unaffected.
type ConnectorStore interface {
	// Keyorix Connect per-reference grants (ADR-045). ListConnectRefGrantsByConnector
	// returns the grants scoped to one connector (the enforcement path);
	// ListConnectRefGrants returns all grants (management/listing).
	ListConnectRefGrantsByConnector(ctx context.Context, connector string) ([]*models.ConnectRefGrant, error)
	ListConnectRefGrants(ctx context.Context) ([]*models.ConnectRefGrant, error)
	CreateConnectRefGrant(ctx context.Context, grant *models.ConnectRefGrant) (*models.ConnectRefGrant, error)
	DeleteConnectRefGrant(ctx context.Context, id uint) error

	// GetProjectByName resolves a project by name, case-insensitively, matching the
	// same LOWER(name) WHERE deleted_at IS NULL partial unique index Project.Name's
	// own uniqueness is enforced by (ensureProjectNameIndex) — a soft-deleted
	// project's name must not resolve here, consistent with it being freed for reuse.
	// Returns a "not found"-substring error (matching GetProject's own convention)
	// when no live project matches.
	GetProjectByName(ctx context.Context, name string) (*models.Project, error)

	// GetConnectorProjectBinding returns the persisted project-ID binding for a
	// Connect connector (ADR-082) — see ConnectorProjectBinding's own doc comment for
	// why boot-time resolution is pinned by ID rather than re-resolved by name on
	// every boot. Returns a "not found"-substring error if the connector has no
	// binding yet (first boot for that connector).
	GetConnectorProjectBinding(ctx context.Context, connector string) (*models.ConnectorProjectBinding, error)
	// CreateConnectorProjectBinding persists a connector's first-boot project
	// resolution (ADR-082): the connector name, the resolved project ID, and the
	// project's name at resolution time (for later rename detection).
	CreateConnectorProjectBinding(ctx context.Context, binding *models.ConnectorProjectBinding) (*models.ConnectorProjectBinding, error)
	// ListConnectorProjectBindings returns every persisted connector→project
	// binding row (#1477's orphan-detection direction: a binding whose connector
	// name is no longer in cfg.Connect.Connectors). Boot-time-diagnostic only —
	// GetConnectorProjectBinding/CreateConnectorProjectBinding cover the
	// per-connector resolution path this does not participate in.
	ListConnectorProjectBindings(ctx context.Context) ([]*models.ConnectorProjectBinding, error)
}

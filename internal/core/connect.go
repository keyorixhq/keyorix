// connect.go — Keyorix Connect (ADR-043): authorized, audited read-through to
// external secret stores. The HTTP layer gates access with RBAC; this layer resolves
// the named connector, proxies the read, and audits it. Values are never persisted.
package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/connect"
)

// EventConnectSecretRead is audited on every federated read (success or failure is
// distinguished by the description).
const EventConnectSecretRead = "connect.secret_read"

// SetConnectManager wires the configured external-store connectors (ADR-043). nil
// (the default) leaves Keyorix Connect disabled.
func (c *KeyorixCore) SetConnectManager(m *connect.Manager) {
	c.connectManager = m
}

// ConnectEnabled reports whether any external-store connector is configured.
func (c *KeyorixCore) ConnectEnabled() bool {
	return c.connectManager != nil && len(c.connectManager.Names()) > 0
}

// ConnectConnectorNames lists the configured connector names (for discovery).
func (c *KeyorixCore) ConnectConnectorNames() []string {
	if c.connectManager == nil {
		return nil
	}
	return c.connectManager.Names()
}

// ReadFederatedSecret proxies a read of ref from the named external-store connector
// and audits it. The caller (HTTP layer) must have already enforced RBAC. The value
// is returned to the caller and never persisted.
func (c *KeyorixCore) ReadFederatedSecret(ctx context.Context, actorID uint, connectorName, ref string) (string, error) {
	if c.connectManager == nil {
		return "", fmt.Errorf("keyorix connect is not enabled")
	}
	conn, ok := c.connectManager.Get(connectorName)
	if !ok {
		return "", fmt.Errorf("unknown connector %q", connectorName)
	}
	uid := actorID
	value, err := conn.GetSecret(ctx, ref)
	if err != nil {
		c.writeAuditEvent(ctx, EventConnectSecretRead, &uid, nil,
			fmt.Sprintf("federated read FAILED via connector %q (%s) ref %q: %v", connectorName, conn.Type(), ref, err))
		return "", err
	}
	c.writeAuditEvent(ctx, EventConnectSecretRead, &uid, nil,
		fmt.Sprintf("federated read via connector %q (%s) ref %q", connectorName, conn.Type(), ref))
	return value, nil
}

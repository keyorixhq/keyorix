// connect.go — Keyorix Connect (ADR-043): authorized, audited read-through to
// external secret stores. The HTTP layer gates access with RBAC; this layer resolves
// the named connector, proxies the read, and audits it. Values are never persisted.
package core

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/connect"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// EventConnectSecretRead is audited on every federated read (success or failure is
// distinguished by the description).
const EventConnectSecretRead = "connect.secret_read"

// Per-reference grant management events (ADR-045).
const (
	EventConnectRefGrantCreate = "connect.ref_grant_create"
	EventConnectRefGrantDelete = "connect.ref_grant_delete"
)

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
// and audits it. The caller (transport layer) must have already enforced the global
// connect.read permission; actorType ("user" / "machine_identity") and principalID
// identify the caller for per-reference RBAC (ADR-045). The audit events this writes
// are stamped with actorType directly (via WithActorType) rather than trusting that
// the caller's ctx already carries the matching tag — a machine-identity read must be
// attributed as ActorTypeMachine (ADR-023) even if a future/CLI caller reaches this
// function with an untagged context, not silently default to "user". The value is
// returned to the caller and never persisted.
func (c *KeyorixCore) ReadFederatedSecret(ctx context.Context, actorType string, principalID uint, connectorName, ref string) (string, error) {
	if c.connectManager == nil {
		return "", fmt.Errorf("keyorix connect is not enabled")
	}
	conn, ok := c.connectManager.Get(connectorName)
	if !ok {
		return "", fmt.Errorf("unknown connector %q", connectorName)
	}
	ctx = WithActorType(ctx, actorType)
	uid := principalID

	// Per-reference RBAC (ADR-045): once a connector has any ref-grant, the read is
	// permitted only if one of the caller's roles holds a matching grant. A connector
	// with no grants is governed solely by connect.read + allowed_refs (unchanged).
	allowed, err := c.connectRefAllowed(ctx, actorType, principalID, connectorName, ref)
	if err != nil {
		return "", err
	}
	if !allowed {
		c.writeAuditEvent(ctx, EventConnectSecretRead, &uid, nil,
			fmt.Sprintf("federated read DENIED by per-reference policy: connector %q (%s) ref %q", connectorName, conn.Type(), ref))
		return "", fmt.Errorf("ref %q is not permitted for your roles on connector %q", ref, connectorName)
	}

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

// ListConnectRefGrants returns every per-reference grant (ADR-045), for management.
func (c *KeyorixCore) ListConnectRefGrants(ctx context.Context) ([]*models.ConnectRefGrant, error) {
	return c.storage.ListConnectRefGrants(ctx)
}

// CreateConnectRefGrant adds a per-reference grant (ADR-045): role roleID may read any
// ref under refPrefix ("" = all) on connectorName. The connector must be configured —
// scoping a non-existent (typo'd) connector is rejected so an operator can't believe
// they restricted a connector that is in fact still unscoped. expiresAt makes the
// grant time-bound (nil = permanent), mirroring UserRole.ExpiresAt / ShareRecord.
// ExpiresAt — a Connect grant is otherwise permanent with no way to make it JIT.
// Audited.
func (c *KeyorixCore) CreateConnectRefGrant(ctx context.Context, actorID, roleID uint, connectorName, refPrefix string, expiresAt *time.Time) (*models.ConnectRefGrant, error) {
	if c.connectManager == nil {
		return nil, fmt.Errorf("keyorix connect is not enabled")
	}
	if _, ok := c.connectManager.Get(connectorName); !ok {
		return nil, fmt.Errorf("unknown connector %q", connectorName)
	}
	if roleID == 0 {
		return nil, fmt.Errorf("a role is required for a connect ref-grant")
	}
	g, err := c.storage.CreateConnectRefGrant(ctx, &models.ConnectRefGrant{
		RoleID:    roleID,
		Connector: connectorName,
		RefPrefix: refPrefix,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return nil, err
	}
	uid := actorID
	c.writeAuditEvent(ctx, EventConnectRefGrantCreate, &uid, nil,
		fmt.Sprintf("connect ref-grant: role %d may read ref-prefix %q on connector %q", roleID, refPrefix, connectorName))
	return g, nil
}

// DeleteConnectRefGrant removes a per-reference grant by id. Audited.
func (c *KeyorixCore) DeleteConnectRefGrant(ctx context.Context, actorID, id uint) error {
	if err := c.storage.DeleteConnectRefGrant(ctx, id); err != nil {
		return err
	}
	uid := actorID
	c.writeAuditEvent(ctx, EventConnectRefGrantDelete, &uid, nil,
		fmt.Sprintf("connect ref-grant %d deleted", id))
	return nil
}

// connectRefAllowed applies the per-reference RBAC policy (ADR-045) for a federated
// read. It returns true when the connector has no ref-grants (the policy is opt-in,
// per connector), or when one of the caller's roles holds a grant whose RefPrefix is a
// prefix of ref. Otherwise the read is denied — deny-by-default once a connector is
// scoped, so a principal whose roles do not match (including one with no resolvable
// roles) cannot read from a grant-scoped connector.
func (c *KeyorixCore) connectRefAllowed(ctx context.Context, actorType string, principalID uint, connectorName, ref string) (bool, error) {
	grants, err := c.storage.ListConnectRefGrantsByConnector(ctx, connectorName)
	if err != nil {
		return false, fmt.Errorf("connect ref-grant lookup: %w", err)
	}
	if len(grants) == 0 {
		return true, nil // no per-ref policy for this connector
	}
	roleSet, err := c.actorRoleIDs(ctx, actorType, principalID)
	if err != nil {
		return false, err
	}
	now := time.Now()
	for _, g := range grants {
		if roleSet[g.RoleID] && connectGrantActive(g, now) && refMatches(g.RefPrefix, ref) {
			return true, nil
		}
	}
	return false, nil
}

// connectGrantActive reports whether a Connect ref-grant still authorizes at time now:
// a nil ExpiresAt is permanent, otherwise the grant stops authorizing the instant it
// passes — mirroring shareActive / UserRole.ExpiresAt. An expired grant is denied
// immediately here; a background sweep is not required for correctness.
func connectGrantActive(g *models.ConnectRefGrant, now time.Time) bool {
	return g.ExpiresAt == nil || now.Before(*g.ExpiresAt)
}

// refMatches reports whether ref is covered by a grant's pattern (ADR-045). A pattern
// with no glob metacharacters (*, ?, [) is matched as a PREFIX — backward compatible,
// and "" matches everything. A pattern containing a metacharacter is matched as a
// shell-style glob via path.Match, where * does not cross '/'. So "metrics/" still
// grants everything under metrics/, "metrics/*" grants exactly one further path
// segment, and "prod/*/db" matches prod/<env>/db. A malformed glob matches nothing.
func refMatches(pattern, ref string) bool {
	if !strings.ContainsAny(pattern, "*?[") {
		return strings.HasPrefix(ref, pattern)
	}
	ok, err := path.Match(pattern, ref)
	return err == nil && ok
}

// actorRoleIDs resolves the caller's EFFECTIVE role IDs the same way canonical
// authorization does, so the per-reference policy matches the rest of RBAC: machine
// identities resolve from machine_identity_roles; users resolve their direct roles
// PLUS group-derived roles (scopedRoleIDs). Resolving only direct roles would deny a
// user whose granted role comes via a group even though connect.read itself honors it.
// Connect is a global surface, so roles are resolved at global scope.
func (c *KeyorixCore) actorRoleIDs(ctx context.Context, actorType string, principalID uint) (map[uint]bool, error) {
	var ids []uint
	var err error
	if actorType == ActorTypeMachine {
		ids, err = c.storage.GetMachineRoleIDsAt(ctx, principalID, Scope{})
		if err != nil {
			return nil, fmt.Errorf("connect ref-grant: load machine roles: %w", err)
		}
	} else {
		ids, err = c.scopedRoleIDs(ctx, principalID, Scope{})
		if err != nil {
			return nil, fmt.Errorf("connect ref-grant: load actor roles: %w", err)
		}
	}
	set := make(map[uint]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set, nil
}

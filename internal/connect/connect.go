// Package connect implements Keyorix Connect (ADR-043): read-through federation to
// external secret stores. A Connector fetches the CURRENT value of a secret held in
// an external store (AWS Secrets Manager, and later GCP Secret Manager / Vault) on
// demand — Keyorix never imports or persists the value, it proxies an authorized,
// audited read. This lets teams reach existing external secrets through Keyorix's
// RBAC and audit trail without migrating them.
//
// Opt-in and disabled by default; each connector's backend SDK is contained behind
// an interface seam so the engine is unit-tested with a fake.
package connect

import (
	"context"
	"strings"
)

// prefixAllowed reports whether ref is permitted by an allowlist of prefixes. An
// empty allowlist permits everything (the backend identity's own scope is then the
// only bound). Shared by the connectors as a defense-in-depth guardrail (ADR-043).
func prefixAllowed(allowed []string, ref string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, p := range allowed {
		if p != "" && refWithinPrefix(p, ref) {
			return true
		}
	}
	return false
}

// refWithinPrefix reports whether ref is scoped by prefix p on a path-segment
// boundary rather than a bare substring match: ref must equal p exactly, or extend
// it starting with '/'. This stops a prefix such as "db/prod" from also matching
// the unrelated sibling "db/production-other-team" — an over-grant a plain
// strings.HasPrefix would allow. A prefix already ending in '/' is treated as
// already segment-scoped (any continuation is fine).
func refWithinPrefix(p, ref string) bool {
	if ref == p {
		return true
	}
	if !strings.HasPrefix(ref, p) {
		return false
	}
	if strings.HasSuffix(p, "/") {
		return true
	}
	return ref[len(p)] == '/'
}

// Connector reads a secret value from one external store. It is read-only: there is
// no create/update/delete — federation proxies reads, it does not own the secret.
type Connector interface {
	// Name is the operator-assigned connector name (the API path key); unique per
	// deployment.
	Name() string
	// Type identifies the backend kind, e.g. "aws-secrets-manager".
	Type() string
	// GetSecret returns the current value of the referenced secret. ref is
	// connector-specific (for AWS Secrets Manager: the secret name or ARN).
	GetSecret(ctx context.Context, ref string) (string, error)
}

// Manager holds the configured connectors, keyed by name.
type Manager struct {
	connectors map[string]Connector
}

// NewManager builds a Manager from the configured connectors (last-wins on a
// duplicate name).
func NewManager(connectors []Connector) *Manager {
	m := &Manager{connectors: make(map[string]Connector, len(connectors))}
	for _, c := range connectors {
		if c != nil && c.Name() != "" {
			m.connectors[c.Name()] = c
		}
	}
	return m
}

// Get returns the connector with the given name.
func (m *Manager) Get(name string) (Connector, bool) {
	if m == nil {
		return nil, false
	}
	c, ok := m.connectors[name]
	return c, ok
}

// Names returns the configured connector names (for listing/discovery).
func (m *Manager) Names() []string {
	if m == nil {
		return nil
	}
	out := make([]string, 0, len(m.connectors))
	for name := range m.connectors {
		out = append(out, name)
	}
	return out
}

// Package rotation implements backend rotation executors (ADR-047): given a reference
// and a freshly generated value, an executor applies that credential to an upstream
// system (e.g. ALTER ROLE on a database), so an externally-owned secret can be rotated
// in place — not just regenerated inside Keyorix. The backend driver/SDK is contained
// behind each Executor (with a fake-able inner seam), and the Manager is the
// name→executor registry the core consumes.
package rotation

import (
	"context"
	"strings"
)

// Executor applies a new credential to an upstream system during rotation. Rotate sets
// the credential identified by ref (e.g. a database role name) to newValue. It must
// fail (return a non-nil error) rather than partially apply, so the caller only records
// the new value in Keyorix once the upstream change succeeded.
type Executor interface {
	// Name is the operator-assigned backend name (the registry key); unique per install.
	Name() string
	// Type identifies the backend kind, e.g. "postgresql".
	Type() string
	// Rotate applies newValue to the credential named ref in the backing system.
	Rotate(ctx context.Context, ref, newValue string) error
}

// Manager holds the configured rotation executors, keyed by name.
type Manager struct {
	execs map[string]Executor
}

// NewManager builds a manager from the given executors (later entries win on a name
// collision, though operators should keep names unique).
func NewManager(execs []Executor) *Manager {
	m := &Manager{execs: make(map[string]Executor, len(execs))}
	for _, e := range execs {
		if e != nil {
			m.execs[e.Name()] = e
		}
	}
	return m
}

// Get returns the executor registered under name.
func (m *Manager) Get(name string) (Executor, bool) {
	e, ok := m.execs[name]
	return e, ok
}

// Names lists the configured backend names (for discovery), in no particular order.
func (m *Manager) Names() []string {
	names := make([]string, 0, len(m.execs))
	for n := range m.execs {
		names = append(names, n)
	}
	return names
}

// prefixAllowed reports whether ref is permitted by an allowed-refs prefix allowlist: an
// empty list places no restriction; otherwise ref must begin with one of the prefixes.
// A guardrail on top of the backend admin identity's own privileges.
func prefixAllowed(allowed []string, ref string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, p := range allowed {
		if p != "" && strings.HasPrefix(ref, p) {
			return true
		}
	}
	return false
}

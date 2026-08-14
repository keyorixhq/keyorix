// Package rotation implements backend rotation executors (ADR-047): given a reference
// and a freshly generated value, an executor applies that credential to an upstream
// system (e.g. ALTER ROLE on a database), so an externally-owned secret can be rotated
// in place — not just regenerated inside Keyorix. The backend driver/SDK is contained
// behind each Executor (with a fake-able inner seam), and the Manager is the
// name→executor registry the core consumes.
package rotation

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// PartialRotationError reports that the upstream rotation minted the new credential
// (Value is the value to store in Keyorix) but a follow-up step failed — typically a
// prior, possibly compromised credential that could not be deleted. The new Value
// MUST still be stored (a cloud key API often returns the private key material only
// once, so discarding it would orphan a live key), while the failure is surfaced so
// an operator removes the leftover credential — the rotation did not fully invalidate
// the old one. Err is the underlying cause.
type PartialRotationError struct {
	Value string
	Err   error
}

func (e *PartialRotationError) Error() string { return e.Err.Error() }
func (e *PartialRotationError) Unwrap() error { return e.Err }

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

// GeneratingExecutor is a rotation backend whose UPSTREAM mints the new value — e.g. a
// cloud access-key API that issues a fresh key pair — rather than accepting a
// Keyorix-generated one. GenerateUpstream performs the upstream rotation and returns the
// new value to store in Keyorix (the candidate value the caller generated is ignored
// for such backends). A backend signals this capability by implementing the interface;
// the rotation flow prefers GenerateUpstream over Rotate when it is present.
type GeneratingExecutor interface {
	Executor
	GenerateUpstream(ctx context.Context, ref string) (string, error)
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

// isAlnumByte reports whether b is an ASCII letter or digit. Anything else — '_', '-',
// '.', '/', ':', a quote, a space — counts as an explicit boundary between identifier
// segments for prefixAllowed below.
func isAlnumByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// prefixAllowed reports whether ref is permitted by an allowed-refs prefix allowlist: an
// empty list places no restriction; otherwise ref must equal one of the entries, or
// extend one at an explicit segment boundary — never merely share a prefix with one. A
// guardrail on top of the backend admin identity's own privileges.
//
// #G46: a raw strings.HasPrefix let an allowed_refs entry of "myapp" also admit
// "myapp2"/"myappadmin" — an unintended superset an operator who configured "myapp"
// (without a trailing delimiter) would not expect. The match must now land on an
// explicit boundary: either the configured prefix's own last character is already
// non-alphanumeric (the pre-existing convention of e.g. "app_" already relies on this —
// the operator's own choice already delimits it), or ref's very next character after the
// prefix is.
func prefixAllowed(allowed []string, ref string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, p := range allowed {
		if p == "" {
			continue
		}
		if ref == p {
			return true
		}
		if !strings.HasPrefix(ref, p) {
			continue
		}
		if !isAlnumByte(p[len(p)-1]) || !isAlnumByte(ref[len(p)]) {
			return true
		}
	}
	return false
}

// sqlStringLiteral matches a single-quoted SQL string literal, including the
// standard ”-doubling escape for an embedded quote (used by both PostgreSQL
// and MySQL's default ANSI_QUOTES-off mode).
var sqlStringLiteral = regexp.MustCompile(`'(?:[^']|'')*'`)

// redactSQLError wraps err with a value-free message: the SQL rotation backends
// (postgres.go, mysql.go) inline the new password into an ALTER ROLE/USER
// statement as a quoted literal, and a driver error can echo the failing
// statement or its position back verbatim (e.g. a syntax error near the
// literal) — %w/%v-wrapping that raw error let the LIVE credential egress into
// the rotation-failure SIEM audit Description and the Slack/webhook broadcast
// on a statement-echoing failure (#132). Any single-quoted literal in the
// error text is replaced with a placeholder before the error is ever wrapped,
// so the operator still gets the backend name, ref, and whatever non-literal
// diagnostic context (error class, position) the driver returned.
func redactSQLError(backend, ref string, err error) error {
	redacted := sqlStringLiteral.ReplaceAllString(err.Error(), "'***'")
	return fmt.Errorf("%s: rotate %q: %s", backend, ref, redacted)
}

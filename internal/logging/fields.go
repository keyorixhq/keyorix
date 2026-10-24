// Package logging gives the server one consistent log shape for production
// operators: structured JSON lines with the same fields on every line, request
// correlation from the REST edge through core to the audit-write path, and a
// scrubber so a secret value that reaches a log call is not written out.
//
// The server logs almost entirely through the standard library `log` package.
// Setup("json", w) does not replace those call sites; it routes `log` output through
// an adapter that emits one JSON object per line (ts, level, msg) and lets
// request-scoped call sites add request_id, principal_type and route.
//
// Request context lives in a Holder placed on the context by the first middleware
// and filled in as the request moves down the stack (id at the edge, principal
// after authentication, route when chi has matched). Core receives the same context
// the handler passes it, so core log lines carry the request_id too. Audit writes
// that must outlive the request copy the holder (core.DetachedAuditContext).
//
// The id is minted by the server (SetServerRequestID). A caller's own X-Request-ID is
// kept apart as ClientRequestID. Only a server-minted id reaches the audit_events row
// (ServerRequestID), where it is stored outside the hash chain as an advisory
// correlation field; see docs/specs/audit-request-id.md.
package logging

import (
	"context"
	"strings"
	"sync"
)

// Principal types: the closed set a log line's principal_type can take.
const (
	PrincipalAnonymous = "anonymous"
	PrincipalUser      = "user"
	PrincipalMachine   = "machine_identity"
	PrincipalSystem    = "system"
)

// maxRequestIDLen caps the request id so a client-supplied X-Request-ID cannot bloat
// every log line of its request.
const maxRequestIDLen = 128

// Fields is a snapshot of the request-scoped log fields.
type Fields struct {
	RequestID string
	// ClientRequestID is the caller's own X-Request-ID, sanitised. Logged for the
	// caller's correlation only; it is never the request's id and never audited.
	ClientRequestID string
	PrincipalType   string
	Route           string
}

// Holder carries a request's log fields. It is shared by pointer through the context
// so a later middleware (authentication, routing) can fill in what an earlier one
// could not know.
type Holder struct {
	mu sync.Mutex
	f  Fields
	// minted is true while f.RequestID was set by SetServerRequestID. Any other
	// setter clears it, so ServerRequestID can never return an externally supplied id.
	minted bool
}

type holderKey struct{}

// WithHolder returns ctx carrying a new Holder, or ctx unchanged with the existing
// Holder when it already has one.
func WithHolder(ctx context.Context) (context.Context, *Holder) {
	if h := HolderFrom(ctx); h != nil {
		return ctx, h
	}
	h := &Holder{}
	return context.WithValue(ctx, holderKey{}, h), h
}

// WithExistingHolder attaches h (typically taken from a request context) to ctx,
// for work that must outlive the request and so runs on a fresh context.
func WithExistingHolder(ctx context.Context, h *Holder) context.Context {
	if h == nil {
		return ctx
	}
	return context.WithValue(ctx, holderKey{}, h)
}

// HolderFrom returns the context's Holder, or nil.
func HolderFrom(ctx context.Context) *Holder {
	if ctx == nil {
		return nil
	}
	h, _ := ctx.Value(holderKey{}).(*Holder)
	return h
}

// FromContext snapshots the context's fields (the zero Fields when there is no
// Holder, e.g. a scheduler tick).
func FromContext(ctx context.Context) Fields {
	if h := HolderFrom(ctx); h != nil {
		return h.Snapshot()
	}
	return Fields{}
}

// Snapshot copies the fields.
func (h *Holder) Snapshot() Fields {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.f
}

// SetRequestID records an externally supplied request id after sanitising it: control
// characters are dropped, characters outside printable ASCII are replaced, and the
// length is capped. An id that sanitises to nothing is ignored. The id is not
// server-minted, so ServerRequestID ignores it.
func (h *Holder) SetRequestID(id string) {
	id = SanitizeID(id)
	if id == "" {
		return
	}
	h.mu.Lock()
	h.f.RequestID = id
	h.minted = false
	h.mu.Unlock()
}

// SetServerRequestID records an id the server minted itself. It is the only setter
// whose value ServerRequestID returns.
func (h *Holder) SetServerRequestID(id string) {
	id = SanitizeID(id)
	if id == "" {
		return
	}
	h.mu.Lock()
	h.f.RequestID = id
	h.minted = true
	h.mu.Unlock()
}

// SetClientRequestID records the caller's own X-Request-ID (sanitised) as a separate
// log field. An id that sanitises to nothing is ignored.
func (h *Holder) SetClientRequestID(id string) {
	id = SanitizeID(id)
	if id == "" {
		return
	}
	h.mu.Lock()
	h.f.ClientRequestID = id
	h.mu.Unlock()
}

// ServerRequestID returns the context's request id when the server minted it, and ""
// otherwise (no holder, or an id that came from outside). The audit writer stores
// only this value.
func ServerRequestID(ctx context.Context) string {
	h := HolderFrom(ctx)
	if h == nil {
		return ""
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.minted {
		return ""
	}
	return h.f.RequestID
}

// SetPrincipalType records which kind of principal the request authenticated as. A
// value outside the closed set is recorded as "anonymous" so a bug elsewhere cannot
// put free text in the field.
func (h *Holder) SetPrincipalType(t string) {
	switch t {
	case PrincipalUser, PrincipalMachine, PrincipalSystem, PrincipalAnonymous:
	default:
		t = PrincipalAnonymous
	}
	h.mu.Lock()
	h.f.PrincipalType = t
	h.mu.Unlock()
}

// SetRoute records the matched route pattern (never the raw path).
func (h *Holder) SetRoute(route string) {
	h.mu.Lock()
	h.f.Route = SanitizeID(route)
	h.mu.Unlock()
}

// SanitizeID makes an externally supplied identifier safe to print: printable
// ASCII only (anything else becomes '_'), capped at maxRequestIDLen.
func SanitizeID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= maxRequestIDLen {
			break
		}
		if r >= 0x21 && r <= 0x7e {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
		n++
	}
	return b.String()
}

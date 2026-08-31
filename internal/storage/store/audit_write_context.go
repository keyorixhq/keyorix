package store

import (
	"context"
	"time"
)

// auditWriteTimeout bounds an audit write once it's detached from its caller's own
// cancellation/deadline (see auditWriteContext) — generous on purpose (an audit insert,
// local or forwarded, is normally single-digit milliseconds; this is a safety net
// against a wedged storage backend or unreachable hub, not a performance budget), per
// this repo's own stated timeout philosophy: timeouts detect hangs, they don't enforce
// speed.
const auditWriteTimeout = 10 * time.Second

// auditWriteContext detaches parent from its own cancellation and deadline, keeping
// every value on it (actor/impersonation/machine-actor tags an audit write may still
// need to read), and bounds the result with auditWriteTimeout instead (#1650).
//
// Every LogAuditEvent implementation calls this before doing any I/O. Four call sites
// across the codebase reach LogAuditEvent: core.KeyorixCore.emitAudit (the shared choke
// point for ~190 Log*/writeAuditEvent* helpers), server/main.go's shutdown-audit write,
// server/http/handlers/audit_ingest_proxy.go's remote-event ingestion, and
// internal/core/anomaly.go's business-hours-config audit. All four pass a context that
// traces back to an inbound HTTP/gRPC request (or, for two of them, that request's
// cancellation propagated through several layers) — so without this, any of them can
// turn "the mutation/event committed" into "committed with zero audit record" purely
// because the triggering client disconnected in the window between the two writes
// completing. Fixing this ONCE here, at the two concrete LogAuditEvent implementations
// (LocalStorage's and RemoteStorage's) rather than at each of those four call sites (or
// the ~190 sites emitAudit itself fans out to), closes the gap for all of them by
// construction, including any future caller that reaches either implementation a fifth
// way.
func auditWriteContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), auditWriteTimeout)
}

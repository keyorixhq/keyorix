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
// Every LogAuditEvent implementation calls this before doing any I/O. Several call
// sites across the codebase reach LogAuditEvent, including core.KeyorixCore.emitAudit
// (the shared choke point for ~190 Log*/writeAuditEvent* helpers), server/main.go's
// shutdown-audit write, and internal/core/anomaly.go's business-hours-config audit —
// several of which pass a context that traces back to an inbound HTTP/gRPC request (or
// that request's cancellation propagated through several layers) — so without this,
// any of them can turn "the mutation/event committed" into "committed with zero audit
// record" purely because the triggering client disconnected in the window between the
// two writes completing. Fixing this ONCE here, at LocalStorage's LogAuditEvent
// implementation, rather than at each call site (or the ~190 sites emitAudit itself
// fans out to), closes the gap for all of them by construction, including any future
// caller that reaches the implementation a new way.
func auditWriteContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), auditWriteTimeout)
}

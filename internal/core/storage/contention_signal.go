package storage

import (
	"context"
	"errors"
	"sync/atomic"
)

// ContentionSignal records, for one request, that the SQLite write gate gave up
// (ErrSQLiteWriteContention) on one of that request's write transactions.
//
// Why a signal and not just errors.Is on the returned error: HTTP handlers turn
// a storage error into a fixed client message and a status (~1300 sendError call
// sites), so by the time the response is written the sentinel is gone. The
// transport layer (server/middleware.WriteContention, the gRPC
// WriteContentionInterceptor) installs a signal in the request context; the gate
// marks it at the moment it times out; the transport reads it when a handler
// answers with a generic internal error and maps that answer to 503 /
// codes.Unavailable instead. One place classifies, no handler is touched.
//
// The signal is request-scoped state, not a verdict: it says "a write of this
// request timed out on the gate", never "this response is because of it". The
// transports therefore only act on a response that is already an internal error.
type ContentionSignal struct{ hit atomic.Bool }

// Hit reports whether the gate timed out for this request.
func (s *ContentionSignal) Hit() bool { return s != nil && s.hit.Load() }

type contentionSignalKey struct{}

// WithContentionSignal returns ctx carrying a fresh signal, and the signal.
func WithContentionSignal(ctx context.Context) (context.Context, *ContentionSignal) {
	s := &ContentionSignal{}
	return context.WithValue(ctx, contentionSignalKey{}, s), s
}

// ContentionSignalFrom returns the signal installed in ctx, or nil.
func ContentionSignalFrom(ctx context.Context) *ContentionSignal {
	s, _ := ctx.Value(contentionSignalKey{}).(*ContentionSignal)
	return s
}

// NoteWriteContention marks ctx's signal, if any. Called by the write gate when
// it returns ErrSQLiteWriteContention. A no-op for a context without a signal
// (background jobs, CLI), so the gate's behaviour is unchanged there.
func NoteWriteContention(ctx context.Context) {
	if s := ContentionSignalFrom(ctx); s != nil {
		s.hit.Store(true)
	}
}

// IsWriteContention reports whether err is (or wraps) the gate's contention
// sentinel. Match with this, never on the message text.
func IsWriteContention(err error) bool {
	return errors.Is(err, ErrSQLiteWriteContention)
}

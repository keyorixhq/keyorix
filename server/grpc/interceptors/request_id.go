package interceptors

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/keyorixhq/keyorix/internal/logging"
)

// RequestIDMetadataKey is the gRPC metadata key carrying the server's request id in
// the response headers, the counterpart of the HTTP X-Request-ID response header. A
// caller may also send it on the request to correlate its own logs with ours; that
// value is recorded only as the client_request_id log field and is never our id.
const RequestIDMetadataKey = "x-request-id"

// RequestIDInterceptor gives every unary RPC a logging.Holder carrying a request id
// the server minted itself, exactly as middleware.LogContext does for HTTP. The audit
// writer stamps audit_events.request_id from that holder (docs/specs/audit-request-id.md),
// so without this interceptor the rows written by a gRPC call have a NULL id.
//
// It must sit outside everything that can write an audit row (right after Recovery),
// and the id is never taken from the request: a client-sent x-request-id is only a
// log field.
func RequestIDInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, id := withServerRequestID(ctx)
		if id != "" {
			// Best effort: an error means the context has no transport stream (a direct
			// handler call in a test), and the call still carries its id.
			_ = grpc.SetHeader(ctx, metadata.Pairs(RequestIDMetadataKey, id))
		}
		return handler(ctx, req)
	}
}

// StreamRequestIDInterceptor is RequestIDInterceptor for streaming RPCs: one id for
// the life of the stream.
func StreamRequestIDInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, id := withServerRequestID(stream.Context())
		if id != "" {
			_ = stream.SetHeader(metadata.Pairs(RequestIDMetadataKey, id))
		}
		return handler(srv, &wrappedServerStream{ServerStream: stream, ctx: ctx})
	}
}

// withServerRequestID returns ctx carrying a holder with a freshly minted server
// request id, and that id ("" when the system random source failed: the call then
// proceeds with no id, and its audit rows record none, rather than a shared
// placeholder).
func withServerRequestID(ctx context.Context) (context.Context, string) {
	ctx, h := logging.WithHolder(ctx)
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get(RequestIDMetadataKey); len(v) > 0 {
			h.SetClientRequestID(v[0])
		}
	}
	id := newServerRequestID()
	if id != "" {
		h.SetServerRequestID(id)
	}
	return ctx, id
}

// newServerRequestID is 24 random hex characters, the same shape as the HTTP id.
func newServerRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

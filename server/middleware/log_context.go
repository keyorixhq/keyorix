package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/logging"
)

// RequestIDHeader is the response header carrying the server's request id. A caller
// (or a reverse proxy) may also send it on the request to correlate its own logs with
// ours; that value is logged as client_request_id and is never our id.
const RequestIDHeader = "X-Request-ID"

// LogContext puts a logging.Holder on the request context and mints the request id: a
// fresh random id every time, never the caller's X-Request-ID, because the id is also
// stored on the request's audit rows (docs/specs/audit-request-id.md). The caller's
// header, sanitised (printable ASCII, capped), is kept as the client_request_id log
// field. The server id is written back into the request header so chi's RequestID
// middleware (registered after this one) adopts it instead of minting a second id.
//
// Register it FIRST, before Recovery, so a panic's log line can carry the id. The
// principal type starts as "anonymous" and is replaced once authentication has run
// (buildRequestContext); the route is filled in by the access logger once chi has
// matched.
func LogContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, h := logging.WithHolder(r.Context())
		h.SetClientRequestID(r.Header.Get(RequestIDHeader))
		id := newRequestID()
		r.Header.Set(RequestIDHeader, id)
		// Echoed so an operator can ask a client "what was the X-Request-ID of the
		// failing call" and grep the logs (and the audit rows) for it.
		w.Header().Set(RequestIDHeader, id)
		h.SetServerRequestID(id)
		h.SetPrincipalType(logging.PrincipalAnonymous)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func newRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unavailable"
	}
	return hex.EncodeToString(b[:])
}

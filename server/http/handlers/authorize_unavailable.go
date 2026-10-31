package handlers

import (
	"log"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
)

// authorizeLookupUnavailableMessage is the fixed 503 text: no storage error detail
// reaches the client. It is the text the REST permission gates and the gRPC
// services answer (server/middleware authorizeLookupUnavailableMessage, unexported
// there); the tests on both sides assert the literal, so a change to one fails the
// other.
const authorizeLookupUnavailableMessage = "authorization temporarily unavailable, please retry"

// authorizeLookupUnavailableRetryAfter is the Retry-After (seconds) the gates send:
// a brief storage blip, not a sustained outage.
const authorizeLookupUnavailableRetryAfter = "2"

// refuseUnlessAuthorized is the in-handler twin of the middleware permission gate's
// verdict: it writes the refusal for the result of a permission check and reports
// whether it did. The caller returns when it is true.
//
//   - err is a storage outage (core.IsAuthorizeTransient): 503 + Retry-After and the
//     fixed message. The caller was not judged, so a client may retry; the request is
//     refused, never served.
//   - any other err, or err == nil with allowed == false: forbidden() writes the
//     handler's own 403, so a genuine denial keeps its status and body. An error the
//     classifier does not recognise stays a fail-closed denial.
//   - err == nil and allowed: false, the handler goes on.
//
// Nothing here grants access: every path that is not "allowed" refuses
// (INV-MW-authorize-lookup-error-is-503).
func refuseUnlessAuthorized(w http.ResponseWriter, r *http.Request, allowed bool, err error, forbidden func()) bool {
	if err != nil {
		if core.IsAuthorizeTransient(r.Context(), err) {
			w.Header().Set("Retry-After", authorizeLookupUnavailableRetryAfter)
			sendError(w, "ServiceUnavailable", authorizeLookupUnavailableMessage, http.StatusServiceUnavailable, nil)
			return true
		}
		log.Printf("WARNING: authorization lookup failed, denying: handler permission check error=%q", err.Error())
	}
	if err != nil || !allowed {
		forbidden()
		return true
	}
	return false
}

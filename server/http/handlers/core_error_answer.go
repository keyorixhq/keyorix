// core_error_answer.go — the REST adapter of the shared error classifier
// (server/errclass): one function that turns a core or storage error into the HTTP
// answer, so a handler's error branch is `answerCoreError(w, r, err, ...)` instead of a
// per-handler switch that classifies by message text and ends in `default: 500`
// (FIX-ERRMAP-STRUCT-1, #4132 #3979 #3873). The gRPC twin is
// server/grpc/services/core_error_status.go; both render errclass.Class through
// errclass.HTTPStatus / errclass.GRPCCode, so REST and gRPC agree by construction.
package handlers

import (
	"log"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/errclass"
)

// coreErrorTexts overrides the fixed client text of a class at one call site, so a
// route keeps the wording its clients and tests know ("Secret not found", "Role
// already assigned to user"). Classes not listed use coreErrorDefaultText.
type coreErrorTexts map[errclass.Class]string

// coreErrorAnswer carries what the adapter needs besides the error.
type coreErrorAnswer struct {
	// op names the operation in the server log of an Internal answer
	// ("creating machine identity"); the client never sees it.
	op string
	// faults is the recorder a handler installed with core.WithAuthorizeFaultRecorder
	// on an operation that authorizes inside core; nil otherwise.
	faults *core.AuthorizeFaultRecorder
	texts  coreErrorTexts
}

// coreErrorCodes is the envelope "error" field per class: today's vocabulary, so a
// client branching on it sees no change.
var coreErrorCodes = map[errclass.Class]string{
	errclass.InvalidInput:     "ValidationError",
	errclass.NotFound:         "NotFound",
	errclass.Conflict:         "ConflictError",
	errclass.Precondition:     "ConflictError",
	errclass.PermissionDenied: "Forbidden",
	errclass.Internal:         "InternalError",
}

// coreErrorDefaultText is the client text of a class when the call site passes none.
// InvalidInput shows the error's own text: core words its validation refusals for the
// caller (the field and the bound) and never echoes caller input (CORE-ERR-FAMILY-7).
// Every other class is fixed: a not-found or conflict wrapped with %w can carry a
// driver message in its text, and Internal is clientSafe by rule
// (TestNoRawErrorTextOnServerErrors).
func coreErrorDefaultText(class errclass.Class, err error) string {
	switch class {
	case errclass.InvalidInput:
		return err.Error()
	case errclass.NotFound:
		return "Resource not found"
	case errclass.Conflict:
		return "Conflict with the current state"
	case errclass.Precondition:
		return "The operation is not allowed in the target's current state"
	case errclass.PermissionDenied:
		return "Insufficient permissions"
	default:
		return clientSafe(err)
	}
}

// answerCoreError writes the HTTP answer for a core or storage error. Order: a partial
// mutation (503 with the applied/not-applied body), an audit outage (503
// audit_unavailable), a storage read fault (503 storage_unavailable), a permission
// lookup outage behind a refusal or an authorize-transient error (503, the gates'
// fixed text, Retry-After), then the class's status with the site's or the default
// text. Internal logs the cause with op and answers clientSafe text. Nothing here
// decides who is allowed: every class is a refusal; only the status and text differ.
func answerCoreError(w http.ResponseWriter, r *http.Request, err error, a coreErrorAnswer) {
	if sendPartialMutation(w, err) || sendAuditUnavailable(w, err) || sendStorageUnavailable(w, err) {
		return
	}
	class := errclass.OfMutation(r.Context(), err, a.faults)
	if class == errclass.Unavailable {
		// A lookup outage, not a verdict: the same answer as the permission gates
		// (refuseUnlessAuthorized), including the denial note on value-read routes.
		cause := errclass.LookupFault(a.faults)
		if cause == nil {
			cause = err
		}
		log.Printf("operation refused, authorization lookup failed (HTTP 503) while %s: %v", a.op, cause)
		core.NoteSecretReadDenial(r.Context(), core.SecretReadDeniedInternalError)
		w.Header().Set("Retry-After", authorizeLookupUnavailableRetryAfter)
		sendError(w, "ServiceUnavailable", authorizeLookupUnavailableMessage, http.StatusServiceUnavailable, nil)
		return
	}
	text, ok := a.texts[class]
	if !ok {
		text = coreErrorDefaultText(class, err)
	}
	if class == errclass.Internal {
		log.Printf("Error %s: %v", a.op, err)
	}
	sendError(w, coreErrorCodes[class], text, errclass.HTTPStatus(class), nil)
}

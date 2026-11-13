// core_error_status.go — the gRPC adapter of the shared error classifier
// (server/errclass): one function that turns a core or storage error into a status,
// so a service's error branch is `coreErrorStatus(ctx, err, ...)` instead of a
// per-family switch that ends in `default: Internal` and drifts from its REST twin
// (FIX-ERRMAP-STRUCT-1, #4020 #3911 #3873). The REST twin is
// server/http/handlers/core_error_answer.go; both render errclass.Class through
// errclass.GRPCCode / errclass.HTTPStatus, so the two transports agree by construction.
package services

import (
	"context"

	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/errclass"
)

// coreErrorTexts overrides the fixed client text of a class at one call site. gRPC
// answers fixed texts for every class (GRPC-003/004: the message never carries a
// driver error, a state name or caller input), so a site that wants core's own
// wording passes it explicitly.
type coreErrorTexts map[errclass.Class]string

// coreErrorStatusOpts carries what the adapter needs besides the error.
type coreErrorStatusOpts struct {
	// op names the operation in the Internal log line and its client text
	// ("role operation failed").
	op string
	// faults is the recorder installed with core.WithAuthorizeFaultRecorder on an
	// operation that authorizes inside core; nil otherwise.
	faults *core.AuthorizeFaultRecorder
	texts  coreErrorTexts
}

// coreErrorDefaultText is the fixed client text of a class.
func coreErrorDefaultText(class errclass.Class, op string) string {
	switch class {
	case errclass.InvalidInput:
		return "invalid request"
	case errclass.NotFound:
		return "not found"
	case errclass.Conflict:
		return "already exists"
	case errclass.Precondition:
		return "not allowed in the target's current state"
	case errclass.PermissionDenied:
		return "insufficient permissions"
	default:
		return op + " failed"
	}
}

// coreErrorStatus is the gRPC status for a core or storage error. Order: an audit
// outage (Unavailable, ErrorInfo audit_unavailable), a storage read fault
// (Unavailable, ErrorInfo storage_unavailable), a permission lookup outage behind a
// refusal or an authorize-transient error (Unavailable, the gates' fixed text), then
// the class's code with the site's or the default text. Internal logs the cause
// (internalFailure keeps the driver cause of a typed fault).
func coreErrorStatus(ctx context.Context, err error, o coreErrorStatusOpts) error {
	if perr, ok := partialMutationStatus(err); ok {
		return perr
	}
	if aerr, ok := auditUnavailableStatus(err); ok {
		return aerr
	}
	if serr, ok := storageUnavailableStatus(err); ok {
		return serr
	}
	class := errclass.OfMutation(ctx, err, o.faults)
	if class == errclass.Unavailable {
		cause := errclass.LookupFault(o.faults)
		if cause == nil {
			cause = err
		}
		return authorizeRefusal(ctx, cause, coreErrorDefaultText(errclass.PermissionDenied, o.op))
	}
	text, ok := o.texts[class]
	if !ok {
		text = coreErrorDefaultText(class, o.op)
	}
	if class == errclass.Internal {
		return internalFailure(text, err)
	}
	return status.Error(errclass.GRPCCode(class), text)
}

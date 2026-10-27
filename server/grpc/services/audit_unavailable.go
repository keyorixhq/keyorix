// audit_unavailable.go — the gRPC answer to a security-relevant mutation whose
// audit row could not be recorded (core.ErrMutationAuditUnavailable: the
// transaction rolled back and nothing was changed). AUDIT-503-MAP-1; the REST
// twin is server/http/handlers/audit_unavailable.go.
package services

import (
	"errors"
	"log"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
)

// auditUnavailableReason is the google.rpc.ErrorInfo reason (the REST error code).
const auditUnavailableReason = "audit_unavailable"

// auditUnavailableRetryAfterSeconds mirrors the REST Retry-After header; gRPC
// carries it in the ErrorInfo metadata (key retry_after_seconds).
const auditUnavailableRetryAfterSeconds = "5"

// auditUnavailableStatus maps err to codes.Unavailable with the sentinel's fixed
// message and a google.rpc.ErrorInfo (reason audit_unavailable, domain
// keyorix.audit) when err unwraps to core.ErrMutationAuditUnavailable, and
// reports whether it did. The wrapped cause (the audit event and the storage
// failure) stays in the server log. Check it in an error mapper before any
// other mapping, which would otherwise answer Internal.
//
// A core.PartialMutationError also unwraps to the sentinel but has its own,
// richer answer (partialMutationStatus); this reports false for it.
func auditUnavailableStatus(err error) (out error, ok bool) {
	if !errors.Is(err, core.ErrMutationAuditUnavailable) {
		return nil, false
	}
	if _, partial := core.AsPartialMutationError(err); partial {
		return nil, false
	}
	log.Printf("mutation refused, audit log unavailable (gRPC Unavailable): %v", err)
	st := status.New(codes.Unavailable, core.MutationAuditUnavailableMessage)
	if withInfo, derr := st.WithDetails(&errdetails.ErrorInfo{
		Reason: auditUnavailableReason, Domain: partialMutationErrorDomain,
		Metadata: map[string]string{"retry_after_seconds": auditUnavailableRetryAfterSeconds},
	}); derr == nil {
		st = withInfo
	}
	return st.Err(), true
}

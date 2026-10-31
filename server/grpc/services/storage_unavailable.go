// storage_unavailable.go — the gRPC answer to an operation whose storage READ failed
// (core.ErrStorageReadUnavailable: a revoke, suspend, unbind, ... that was never
// applied). STORAGE-ERR-CLASS-1; the REST twin is
// server/http/handlers/storage_unavailable.go and the audit-outage sibling is
// audit_unavailable.go (same shape: codes.Unavailable + ErrorInfo, no new response).
package services

import (
	"errors"
	"log"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
)

// storageUnavailableReason is the google.rpc.ErrorInfo reason (the REST error code).
const storageUnavailableReason = "storage_unavailable"

// storageUnavailableRetryAfterSeconds mirrors the REST Retry-After header.
const storageUnavailableRetryAfterSeconds = "5"

// storageUnavailableStatus maps err to codes.Unavailable with the sentinel's fixed
// message and a google.rpc.ErrorInfo (reason storage_unavailable) when err unwraps to
// core.ErrStorageReadUnavailable, and reports whether it did. The wrapped cause (the
// driver failure) stays in the server log. Check it in an error mapper before any
// message-text mapping, which would otherwise answer a fault as NotFound or Internal.
func storageUnavailableStatus(err error) (out error, ok bool) {
	if !errors.Is(err, core.ErrStorageReadUnavailable) {
		return nil, false
	}
	log.Printf("operation refused, storage read failed (gRPC Unavailable): %s", core.StorageReadFaultDetail(err))
	st := status.New(codes.Unavailable, core.StorageReadUnavailableMessage)
	if withInfo, derr := st.WithDetails(&errdetails.ErrorInfo{
		Reason: storageUnavailableReason, Domain: partialMutationErrorDomain,
		Metadata: map[string]string{"retry_after_seconds": storageUnavailableRetryAfterSeconds},
	}); derr == nil {
		st = withInfo
	}
	return st.Err(), true
}

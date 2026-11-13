package services

// core_error_status_test.go — the gRPC adapter of server/errclass renders every row of
// the shared table as errclass.GRPCCode says; the REST adapter's test
// (server/http/handlers/core_error_answer_test.go) asserts the same rows against
// errclass.HTTPStatus. Together they are the REST/gRPC parity check on the sentinel
// errors (FIX-ERRMAP-STRUCT-1 item 3).

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/server/errclass"
)

func TestCoreErrorStatus_EverySentinelRendersItsClass(t *testing.T) {
	for _, s := range errclass.Sentinels() {
		t.Run(s.Name, func(t *testing.T) {
			var err error
			if s.Err == core.ErrStorageReadUnavailable {
				err = core.ReadFault(errors.New("pq: connection refused host=db-prod.internal"))
			} else {
				err = fmt.Errorf("Speicherfehler: %w: pq: duplicate key value violates unique constraint \"idx\"", s.Err)
			}
			got := coreErrorStatus(context.Background(), err, coreErrorStatusOpts{op: "test operation"})
			assert.Equal(t, errclass.GRPCCode(s.Class), status.Code(got), got.Error())
			assert.NotContains(t, status.Convert(got).Message(), "pq:", "a wrapped driver message never reaches the client")
		})
	}
}

func TestCoreErrorStatus_TextsAndDetails(t *testing.T) {
	ctx := context.Background()
	got := coreErrorStatus(ctx, fmt.Errorf("get: %w", storage.ErrRoleNotFound), coreErrorStatusOpts{texts: coreErrorTexts{errclass.NotFound: "role not found"}})
	assert.Equal(t, codes.NotFound, status.Code(got))
	assert.Equal(t, "role not found", status.Convert(got).Message())

	got = coreErrorStatus(ctx, fmt.Errorf("x: %w", core.ErrValidation), coreErrorStatusOpts{})
	assert.Equal(t, codes.InvalidArgument, status.Code(got))
	assert.Equal(t, "invalid request", status.Convert(got).Message())

	got = coreErrorStatus(ctx, fmt.Errorf("x: %w", core.ErrBuiltinRole), coreErrorStatusOpts{})
	assert.Equal(t, codes.PermissionDenied, status.Code(got), "a specific permission sentinel is a refusal")

	got = coreErrorStatus(ctx, errors.New("pq: boom on db-prod"), coreErrorStatusOpts{op: "role operation"})
	assert.Equal(t, codes.Internal, status.Code(got))
	assert.Equal(t, "role operation failed", status.Convert(got).Message())

	// The two outages keep their ErrorInfo details.
	got = coreErrorStatus(ctx, core.ReadFault(errors.New("driver: reset")), coreErrorStatusOpts{})
	assert.Equal(t, codes.Unavailable, status.Code(got))
	assert.True(t, hasErrorInfoReason(got, storageUnavailableReason))
	got = coreErrorStatus(ctx, fmt.Errorf("x: %w", core.ErrMutationAuditUnavailable), coreErrorStatusOpts{})
	assert.Equal(t, codes.Unavailable, status.Code(got))
	assert.True(t, hasErrorInfoReason(got, auditUnavailableReason))

	partial := &core.PartialMutationError{Applied: "removal", NotApplied: "addition", Err: core.ErrMutationAuditUnavailable}
	got = coreErrorStatus(ctx, partial, coreErrorStatusOpts{})
	assert.Equal(t, codes.Unavailable, status.Code(got))
	assert.Equal(t, partial.ClientMessage(), status.Convert(got).Message())

	// An authorize outage is Unavailable with the gates' fixed text; a canceled request too.
	got = coreErrorStatus(ctx, fmt.Errorf("resolve: %w", syscall.ECONNREFUSED), coreErrorStatusOpts{})
	assert.Equal(t, codes.Unavailable, status.Code(got))
	assert.Equal(t, authorizeUnavailableMessage, status.Convert(got).Message())
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	got = coreErrorStatus(canceled, errors.New("boom"), coreErrorStatusOpts{})
	assert.Equal(t, codes.Unavailable, status.Code(got))

	// Text alone is never a class.
	for _, txt := range []string{"record not found", "permission denied", "already exists"} {
		got = coreErrorStatus(ctx, errors.New(txt), coreErrorStatusOpts{op: "op"})
		assert.Equal(t, codes.Internal, status.Code(got), txt)
	}
}

func hasErrorInfoReason(err error, reason string) bool {
	for _, d := range status.Convert(err).Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.Reason == reason {
			return true
		}
	}
	return false
}

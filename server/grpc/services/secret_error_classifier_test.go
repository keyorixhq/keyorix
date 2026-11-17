package services

// secret_error_classifier_test.go — GRPC-MAPPER-TAILS-1 item 3. mapSecretError and the
// share scope resolver answer through coreErrorStatus. The codes and client texts the
// hand-written switch gave for the sentinels it listed stay. What changes: an outage is
// Unavailable, a typed error is never read as text, and a sentinel the old switch did
// not list answers its class instead of Internal "secret operation failed"
// (TestMapSecretError_UnlistedSentinelsAnswerTheirClass).

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
)

func TestMapSecretError_KeepsCodesAndTexts(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code codes.Code
		text string
	}{
		{"missing secret", fmt.Errorf("get: %w", storage.ErrSecretNotFound), codes.NotFound, "secret not found"},
		{"foreign environment", storage.Typed(core.ErrSecretTargetInvalid, "environment 7 not found", nil), codes.NotFound, "secret not found"},
		{"refused", fmt.Errorf("x: %w", core.ErrPermissionDenied), codes.PermissionDenied, "access denied to this secret"},
		{"already exists", storage.Typed(core.ErrSecretAlreadyExists, "secret already exists", nil), codes.AlreadyExists, secretAlreadyExistsText},
		{"duplicate version", fmt.Errorf("x: %w", storage.ErrDuplicateSecretVersion), codes.AlreadyExists, secretAlreadyExistsText},
		{"contention", fmt.Errorf("x: %w", core.ErrSecretVersionContentionExhausted), codes.Aborted, "high write contention on this secret; retry the request"},
		{"rotation text", errors.New("unknown rotation charset: klingon"), codes.InvalidArgument, "invalid rotation configuration"},
		{"unknown", errors.New("unexpected database timeout"), codes.Internal, "secret operation failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapSecretError(context.Background(), tc.err)
			assert.Equal(t, tc.code, status.Code(got), got.Error())
			assert.Equal(t, tc.text, status.Convert(got).Message())
		})
	}
}

// A typed storage read fault whose driver text says "out of range" or "exceeds" is an
// outage, not an invalid rotation configuration: the text match runs last and only for
// an error the classifier calls Internal.
func TestMapSecretError_TypedFaultIsNotReadAsRotationText(t *testing.T) {
	for _, text := range []string{"driver: value out of range", "driver: statement exceeds limit"} {
		fault := core.ReadFault(errors.New(text))
		require.Error(t, fault)
		got := mapSecretError(context.Background(), fmt.Errorf("read: %w", fault))
		assert.Equal(t, codes.Unavailable, status.Code(got), "%s: %v", text, got)
		assert.True(t, hasErrorInfoReason(got, storageUnavailableReason), text)
	}
}

// An audit-outage error is Unavailable with its ErrorInfo, not Internal (the old switch
// had no branch for it).
func TestMapSecretError_AuditOutageIsUnavailable(t *testing.T) {
	got := mapSecretError(context.Background(), fmt.Errorf("update: %w", core.ErrMutationAuditUnavailable))
	assert.Equal(t, codes.Unavailable, status.Code(got), got.Error())
}

// Sentinels the old switch did not list answer their class with the class's default text.
// Only the two name/version conflicts get the "name already exists" text; any other
// conflict (a duplicate dependency) does not.
func TestMapSecretError_UnlistedSentinelsAnswerTheirClass(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code codes.Code
		text string
	}{
		{"invalid input", fmt.Errorf("x: %w", core.ErrSecretInvalidInput), codes.InvalidArgument, "invalid request"},
		{"not deleted", fmt.Errorf("x: %w", core.ErrSecretNotDeleted), codes.FailedPrecondition, "not allowed in the target's current state"},
		{"duplicate dependency", fmt.Errorf("x: %w", storage.ErrDuplicateSecretDependency), codes.AlreadyExists, "already exists"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapSecretError(context.Background(), tc.err)
			assert.Equal(t, tc.code, status.Code(got), got.Error())
			assert.Equal(t, tc.text, status.Convert(got).Message())
		})
	}
}

// ErrSecretAlreadyExists has no sentinel-table row, so mapSecretError answers it in a
// pre-check. That pre-check must not hide an outage the same error also wraps.
func TestMapSecretError_AlreadyExistsDoesNotHideAnOutage(t *testing.T) {
	exists := storage.Typed(core.ErrSecretAlreadyExists, "secret already exists", nil)

	got := mapSecretError(context.Background(), errors.Join(exists, core.ErrMutationAuditUnavailable))
	assert.Equal(t, codes.Unavailable, status.Code(got), got.Error())
	assert.True(t, hasErrorInfoReason(got, auditUnavailableReason))

	got = mapSecretError(context.Background(), errors.Join(exists, core.ReadFault(errors.New("driver: connection reset"))))
	assert.Equal(t, codes.Unavailable, status.Code(got), got.Error())
	assert.True(t, hasErrorInfoReason(got, storageUnavailableReason))

	// A verdict, not an outage: like the table's Conflict rows (a duplicate version), it
	// keeps AlreadyExists under a canceled ctx.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, err := range []error{exists, fmt.Errorf("x: %w", storage.ErrDuplicateSecretVersion)} {
		got = mapSecretError(canceled, err)
		assert.Equal(t, codes.AlreadyExists, status.Code(got), got.Error())
		assert.Equal(t, secretAlreadyExistsText, status.Convert(got).Message())
	}
	// The rotation text match is skipped for an authorize-transient error.
	got = mapSecretError(canceled, errors.New("unknown rotation charset: klingon"))
	assert.Equal(t, codes.Unavailable, status.Code(got), got.Error())

	// A refusal that also says "already exists" stays the refusal (no existence oracle).
	got = mapSecretError(context.Background(), errors.Join(exists, core.ErrPermissionDenied))
	assert.Equal(t, codes.PermissionDenied, status.Code(got), got.Error())
}

// The share scope resolver's read failures keep their answers when rendered by the
// adapter: a canceled ctx is the authorization outage text, a typed fault the storage
// ErrorInfo, an absent row the uniform "share not found".
func TestShareScopeReadError_Answers(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	got := shareScopeReadError(canceled, errors.New("driver: operation interrupted"))
	assert.Equal(t, codes.Unavailable, status.Code(got), got.Error())
	assert.Equal(t, authorizeUnavailableMessage, status.Convert(got).Message())

	// Under a canceled ctx a sentinel-carrying error is still the authorization outage,
	// not answered by its class (NotFound "not found", the storage ErrorInfo).
	for _, err := range []error{
		storage.ErrShareNotFound,
		storage.ErrSecretNotFound,
		fmt.Errorf("read share: %w", core.ErrStorageReadUnavailable),
		fmt.Errorf("authorize: %w", core.ErrPermissionDenied),
	} {
		got = shareScopeReadError(canceled, err)
		assert.Equal(t, codes.Unavailable, status.Code(got), "%v: %v", err, got)
		assert.Equal(t, authorizeUnavailableMessage, status.Convert(got).Message(), "%v", err)
		assert.False(t, hasErrorInfoReason(got, storageUnavailableReason), "%v", err)
	}

	got = shareScopeReadError(context.Background(), errors.New("boom: connection reset by peer"))
	assert.Equal(t, codes.Unavailable, status.Code(got), got.Error())
	assert.True(t, hasErrorInfoReason(got, storageUnavailableReason))
	assert.NotContains(t, status.Convert(got).Message(), "connection reset")

	got = shareScopeReadError(context.Background(), storage.ErrShareNotFound)
	assert.Equal(t, codes.NotFound, status.Code(got), got.Error())
	assert.Equal(t, "share not found", status.Convert(got).Message())
}

package services

// secret_error_classifier_test.go — GRPC-MAPPER-TAILS-1 item 3. mapSecretError and the
// share scope resolver answer through coreErrorStatus. The codes and client texts the
// hand-written switch gave stay; what changes is that an outage is Unavailable and a
// typed error is never read as text.

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

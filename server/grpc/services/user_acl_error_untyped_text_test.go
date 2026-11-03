package services

// ERRSTRING-CLASS-1 item 3: mapSecretACLError and mapUserError no longer read the
// words "invalid"/"required"/"cannot grant this role" in err.Error(). The real core
// refusals are typed and keep their class (core RPC paths below); an untyped storage
// or driver error carrying those words is a server fault.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
)

func TestMapSecretACLError_UntypedDriverTextIsInternal(t *testing.T) {
	for _, text := range []string{
		`pq: invalid input syntax for type bigint: "x"`,
		`pq: null value in column "user_id" (field required)`,
	} {
		got := mapSecretACLError(errors.New(text))
		assert.Equal(t, codes.Internal, status.Code(got), text)
		assert.Equal(t, "ACL operation failed", status.Convert(got).Message())
	}
}

func TestGrantSecretACL_RealValidationRefusalIsInvalidArgument(t *testing.T) {
	r := newSecretTestRig(t)
	c := r.core
	ctx := context.Background()

	err := c.GrantSecretACL(ctx, 1, 1, 2, []string{"not-a-permission"})
	require.Error(t, err)
	got := mapSecretACLError(err)
	assert.Equal(t, codes.InvalidArgument, status.Code(got), got.Error())
	assert.Equal(t, "invalid ACL request", status.Convert(got).Message())

	err = c.GrantSecretACL(ctx, 1, 1, 0, []string{"read"})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(mapSecretACLError(err)))
}

func TestMapUserError_UntypedCeilingPhraseIsInternal(t *testing.T) {
	got := mapUserError(errors.New(`pq: duplicate role label "cannot grant this role"`))
	assert.Equal(t, codes.Internal, status.Code(got), got.Error())
}

func TestMapUserError_TypedRefusalFromRealCorePathIsPermissionDenied(t *testing.T) {
	got := mapUserError(core.ErrPermissionDenied)
	assert.Equal(t, codes.PermissionDenied, status.Code(got))
}

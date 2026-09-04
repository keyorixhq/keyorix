// secret_size_cap_test.go — gRPC-layer coverage for the maximum secret-value
// size cap (Item 1c/1e): exactly-at-limit is accepted, one byte over is
// rejected with codes.ResourceExhausted (core.SecretValueTooLargeError,
// mapped by mapSecretError's errors.As check ahead of its string-matching
// switch -- see the "exceeds" collision this guards against in
// mapSecretError's own comment).
package services

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

func TestSecretService_CreateSecret_SecretSizeCap_ExactlyAtLimit(t *testing.T) {
	r := newSecretTestRig(t)
	r.svc.core.SetMaxSecretSize(100)
	ctx := authCtx(1, "writer", "secrets.write", "secrets.read")

	sec, err := r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name: "at-limit-grpc", Value: strings.Repeat("a", 100),
		ProjectId: 1, EnvironmentId: 1, Type: "password",
	})
	require.NoError(t, err)
	assert.NotZero(t, sec.GetId())
}

func TestSecretService_CreateSecret_SecretSizeCap_OneByteOverRejected(t *testing.T) {
	r := newSecretTestRig(t)
	r.svc.core.SetMaxSecretSize(100)
	ctx := authCtx(1, "writer", "secrets.write", "secrets.read")

	_, err := r.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
		Name: "over-limit-grpc", Value: strings.Repeat("a", 101),
		ProjectId: 1, EnvironmentId: 1, Type: "password",
	})
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "100")
}

func TestSecretService_UpdateSecret_SecretSizeCap_ExactlyAtLimit(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "writer", "secrets.write", "secrets.read")
	created := r.createSecret(t, ctx, "update-at-limit-grpc", "seed")
	r.svc.core.SetMaxSecretSize(100)

	value := strings.Repeat("b", 100)
	updated, err := r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{
		Id: created.GetId(), Value: &value,
	})
	require.NoError(t, err)
	assert.Equal(t, created.GetId(), updated.GetId())
}

func TestSecretService_UpdateSecret_SecretSizeCap_OneByteOverRejected(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "writer", "secrets.write", "secrets.read")
	created := r.createSecret(t, ctx, "update-over-limit-grpc", "seed")
	r.svc.core.SetMaxSecretSize(100)

	value := strings.Repeat("b", 101)
	_, err := r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{
		Id: created.GetId(), Value: &value,
	})
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "100")
}

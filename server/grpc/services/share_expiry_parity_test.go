// share_expiry_parity_test.go — regression coverage for GRPC track backlog step
// 4 (functional parity): gRPC's ShareSecret/UpdateSharePermission previously had
// no way to set, extend, or clear a share's expiry — a REST-only capability
// (shares_crud.go's expires_at/clear_expiry body fields) with no gRPC
// equivalent, so a gRPC-only client had no way to create or manage a
// just-in-time (time-bound) share at all. Both surfaces now funnel through the
// SAME core.ShareSecret/UpdateSharePermission, so validation (expiry must be in
// the future) is enforced identically without any gRPC-side duplication.
package services

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

func TestShareService_ShareSecret_WithExpiresAt(t *testing.T) {
	r := newShareTestRig(t)
	future := time.Now().Add(24 * time.Hour)

	rec, err := r.svc.ShareSecret(ownerCtx(), &pb.ShareSecretRequest{
		SecretId: r.secretID, RecipientId: 2, Permission: "read",
		ExpiresAt: timestamppb.New(future),
	})
	require.NoError(t, err)
	require.NotNil(t, rec.GetExpiresAt(), "share created via gRPC with expires_at must round-trip it")
	assert.WithinDuration(t, future, rec.GetExpiresAt().AsTime(), time.Second)
}

func TestShareService_ShareSecret_ExpiresAtInPast_Rejected(t *testing.T) {
	r := newShareTestRig(t)
	past := time.Now().Add(-time.Hour)

	_, err := r.svc.ShareSecret(ownerCtx(), &pb.ShareSecretRequest{
		SecretId: r.secretID, RecipientId: 2, Permission: "read",
		ExpiresAt: timestamppb.New(past),
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err),
		"a past expires_at must be rejected the same way REST rejects it (400/ValidationError -> InvalidArgument)")
}

func TestShareService_ShareSecret_NoExpiresAt_IsPermanent(t *testing.T) {
	r := newShareTestRig(t)
	rec := r.share(t, "read")
	assert.Nil(t, rec.GetExpiresAt(), "omitting expires_at must create a permanent share, matching REST")
}

func TestShareService_UpdateSharePermission_SetsExpiresAt(t *testing.T) {
	r := newShareTestRig(t)
	rec := r.share(t, "read")
	require.Nil(t, rec.GetExpiresAt())

	future := time.Now().Add(48 * time.Hour)
	updated, err := r.svc.UpdateSharePermission(ownerCtx(), &pb.UpdateSharePermissionRequest{
		ShareId: rec.GetId(), Permission: "read", ExpiresAt: timestamppb.New(future),
	})
	require.NoError(t, err)
	require.NotNil(t, updated.GetExpiresAt())
	assert.WithinDuration(t, future, updated.GetExpiresAt().AsTime(), time.Second)
}

func TestShareService_UpdateSharePermission_ClearsExpiry(t *testing.T) {
	r := newShareTestRig(t)
	future := time.Now().Add(24 * time.Hour)
	rec, err := r.svc.ShareSecret(ownerCtx(), &pb.ShareSecretRequest{
		SecretId: r.secretID, RecipientId: 2, Permission: "read",
		ExpiresAt: timestamppb.New(future),
	})
	require.NoError(t, err)
	require.NotNil(t, rec.GetExpiresAt())

	updated, err := r.svc.UpdateSharePermission(ownerCtx(), &pb.UpdateSharePermissionRequest{
		ShareId: rec.GetId(), Permission: "read", ClearExpiry: true,
	})
	require.NoError(t, err)
	assert.Nil(t, updated.GetExpiresAt(), "clear_expiry must make the share permanent")
}

func TestShareService_UpdateSharePermission_ExpiresAtInPast_Rejected(t *testing.T) {
	r := newShareTestRig(t)
	rec := r.share(t, "read")
	past := time.Now().Add(-time.Hour)

	_, err := r.svc.UpdateSharePermission(ownerCtx(), &pb.UpdateSharePermissionRequest{
		ShareId: rec.GetId(), Permission: "read", ExpiresAt: timestamppb.New(past),
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestShareService_ShareSecretWithGroup_WithExpiresAt covers the group-share
// branch of ShareSecret, which wires ExpiresAt into a SEPARATE core request type
// (core.GroupShareSecretRequest) than the direct-user branch — a distinct call
// site that needed its own wiring, not something the direct-share test above
// exercises.
func TestShareService_ShareSecretWithGroup_WithExpiresAt(t *testing.T) {
	r := newShareTestRig(t)
	require.NoError(t, r.db.Create(&models.Group{ID: 1, Name: "eng"}).Error)
	// Scope the group to project 1 (IsGroupProjectScoped) via a live role grant.
	require.NoError(t, r.db.Create(&models.GroupRole{GroupID: 1, RoleID: writerRoleID, ProjectID: 1}).Error)

	future := time.Now().Add(24 * time.Hour)
	rec, err := r.svc.ShareSecret(ownerCtx(), &pb.ShareSecretRequest{
		SecretId: r.secretID, RecipientId: 1, IsGroup: true, Permission: "read",
		ExpiresAt: timestamppb.New(future),
	})
	require.NoError(t, err)
	require.NotNil(t, rec.GetExpiresAt(), "a group share created via gRPC with expires_at must round-trip it")
	assert.WithinDuration(t, future, rec.GetExpiresAt().AsTime(), time.Second)
}

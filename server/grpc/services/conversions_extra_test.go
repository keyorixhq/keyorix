package services

import (
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// --- conversions.go helpers ---

// TestClientSafe verifies clientSafe returns a generic string and does not
// expose the raw error message.
func TestClientSafe(t *testing.T) {
	err := status.Error(codes.Internal, "raw internal storage error with credentials")
	msg := clientSafe(err)
	assert.NotEmpty(t, msg, "clientSafe must return a non-empty string")
	assert.NotContains(t, msg, "credentials", "clientSafe must not leak the raw error")

	// Nil input must return empty.
	assert.Empty(t, clientSafe(nil))
}

// TestIsSafeConnectError covers all the known-safe marker strings and an unknown one.
func TestIsSafeConnectError(t *testing.T) {
	safe := []string{
		"keyorix connect is not enabled",
		"unknown connector: vault",
		"a role is required for a connect ref-grant",
		"is not permitted for your roles on connector",
	}
	for _, s := range safe {
		assert.Truef(t, isSafeConnectError(s), "expected %q to be safe", s)
	}
	assert.False(t, isSafeConnectError("raw storage error with dsn"), "unexpected marker must not be safe")
}

// TestNormalizePage covers boundary conditions.
func TestNormalizePage(t *testing.T) {
	p, ps := normalizePage(0, 0)
	assert.Equal(t, 1, p, "page 0 must become 1")
	assert.Equal(t, 20, ps, "pageSize 0 must become default 20")

	p, ps = normalizePage(5, 50)
	assert.Equal(t, 5, p)
	assert.Equal(t, 50, ps)

	p, ps = normalizePage(1, 200) // over cap
	assert.Equal(t, 1, p)
	assert.Equal(t, 20, ps, "pageSize > 100 must become default 20")
}

// TestTotalPages covers the edge cases.
func TestTotalPages(t *testing.T) {
	assert.Equal(t, 0, totalPages(10, 0), "zero pageSize must return 0")
	assert.Equal(t, 1, totalPages(1, 20))
	assert.Equal(t, 2, totalPages(21, 20))
	assert.Equal(t, 5, totalPages(100, 20))
}

// TestIntToU32_Overflow verifies that a negative int is clamped to 0.
func TestIntToU32_Clamps(t *testing.T) {
	assert.Equal(t, uint32(0), intToU32(-1))
	assert.Equal(t, uint32(42), intToU32(42))
}

// TestI64ToU32_Negative clamps negative int64.
func TestI64ToU32_Negative(t *testing.T) {
	assert.Equal(t, uint32(0), i64ToU32(-5))
	assert.Equal(t, uint32(7), i64ToU32(7))
}

// TestIntToI32_Overflow verifies intToI32 clamps on overflow.
func TestIntToI32_Overflow(t *testing.T) {
	// A value that overflows int32 returns 0.
	assert.Equal(t, int32(0), intToI32(int(^uint32(0)>>1)+1))
	assert.Equal(t, int32(10), intToI32(10))
}

// TestIntPtrToInt32Ptr covers the nil and non-nil branches.
func TestIntPtrToInt32Ptr(t *testing.T) {
	assert.Nil(t, intPtrToInt32Ptr(nil))
	v := 5
	got := intPtrToInt32Ptr(&v)
	if assert.NotNil(t, got) {
		assert.Equal(t, int32(5), *got)
	}
}

// TestInt32PtrToIntPtr covers the nil and non-nil branches.
func TestInt32PtrToIntPtr(t *testing.T) {
	assert.Nil(t, int32PtrToIntPtr(nil))
	v := int32(7)
	got := int32PtrToIntPtr(&v)
	if assert.NotNil(t, got) {
		assert.Equal(t, 7, *got)
	}
}

// TestTsToTimePtr covers the nil and non-nil branches.
func TestTsToTimePtr(t *testing.T) {
	assert.Nil(t, tsToTimePtr(nil))
	ts := timestamppb.Now()
	got := tsToTimePtr(ts)
	if assert.NotNil(t, got) {
		assert.WithinDuration(t, ts.AsTime(), *got, time.Second)
	}
}

// TestTimePtrToTs covers the nil and non-nil branches.
func TestTimePtrToTs(t *testing.T) {
	assert.Nil(t, timePtrToTs(nil))
	now := time.Now()
	got := timePtrToTs(&now)
	if assert.NotNil(t, got) {
		assert.WithinDuration(t, now, got.AsTime(), time.Second)
	}
}

// TestOptString covers nil, empty, and non-empty inputs.
func TestOptString(t *testing.T) {
	assert.Nil(t, optString(nil))
	empty := ""
	assert.Nil(t, optString(&empty))
	s := "hello"
	got := optString(&s)
	if assert.NotNil(t, got) {
		assert.Equal(t, "hello", *got)
	}
}

// TestOptUint covers nil, zero, and non-zero inputs.
func TestOptUint(t *testing.T) {
	assert.Nil(t, optUint(nil))
	zero := uint32(0)
	assert.Nil(t, optUint(&zero))
	v := uint32(5)
	got := optUint(&v)
	if assert.NotNil(t, got) {
		assert.Equal(t, uint(5), *got)
	}
}

// TestMetadataToMap covers nil/empty and non-empty JSON.
func TestMetadataToMap(t *testing.T) {
	assert.Equal(t, map[string]string{}, metadataToMap(nil))
	assert.Equal(t, map[string]string{}, metadataToMap(models.JSON{}))
	got := metadataToMap(models.JSON(`{"key":"value"}`))
	assert.Equal(t, map[string]string{"key": "value"}, got)
	// Non-string values: json.Unmarshal into map[string]string produces zero values
	// for non-string entries, resulting in empty-string entries (Go partial unmarshal).
	// The real coverage goal here is that the function doesn't panic.
	result := metadataToMap(models.JSON(`{"key":42}`))
	assert.NotNil(t, result)
}

// TestPtrU32 exercises ptrU32 (defined in audit_service.go) directly.
func TestPtrU32(t *testing.T) {
	v := ptrU32(uint(7))
	require.NotNil(t, v)
	assert.Equal(t, uint32(7), *v)
}

// TestMapProjectError covers all branches of the project error mapper.
func TestMapProjectError(t *testing.T) {
	cases := []struct {
		msg      string
		wantCode codes.Code
	}{
		{"project not found", codes.NotFound},
		{"project already exists", codes.AlreadyExists},
		{"permission denied for this action", codes.PermissionDenied},
		{"access denied for resource", codes.PermissionDenied},
		{"some storage error", codes.Internal},
	}
	for _, c := range cases {
		err := mapProjectError(errFromMsg(c.msg))
		assert.Equalf(t, c.wantCode, status.Code(err), "mapProjectError(%q)", c.msg)
	}
}

// TestMapSecretError covers all branches of the error mapper.
func TestMapSecretError(t *testing.T) {
	cases := []struct {
		msg      string
		wantCode codes.Code
	}{
		{"record not found", codes.NotFound},
		{"permission denied to access", codes.PermissionDenied},
		{"access denied to resource", codes.PermissionDenied},
		{"secret with this name already exists", codes.AlreadyExists},
		{"unknown rotation charset: klingon", codes.InvalidArgument},
		{"rotation length out of range", codes.InvalidArgument},
		{"no rotation backends configured", codes.InvalidArgument},
		{"must be set together for rotation", codes.InvalidArgument},
		{"unknown rotation backend: unknown", codes.InvalidArgument},
		{"value exceeds max allowed", codes.InvalidArgument},
		{"some unexpected error", codes.Internal},
	}
	for _, c := range cases {
		err := mapSecretError(errFromMsg(c.msg))
		assert.Equalf(t, c.wantCode, status.Code(err), "mapSecretError(%q)", c.msg)
	}
}

// TestMapShareError covers all branches of the share error mapper.
func TestMapShareError(t *testing.T) {
	cases := []struct {
		msg      string
		wantCode codes.Code
	}{
		{"share not found", codes.NotFound},
		{"not authorized to revoke", codes.PermissionDenied},
		{"permission denied", codes.PermissionDenied},
		{"unexpected storage failure", codes.Internal},
	}
	for _, c := range cases {
		err := mapShareError(errFromMsg(c.msg))
		assert.Equalf(t, c.wantCode, status.Code(err), "mapShareError(%q)", c.msg)
	}
}

// errFromMsg is a minimal error type for testing error mapper functions.
type errFromMsg string

func (e errFromMsg) Error() string { return string(e) }

// TestSecretNodeToProto_AllFields verifies secretNodeToProto maps all fields correctly.
func TestSecretNodeToProto_AllFields(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	n := &models.SecretNode{
		ID:            42,
		Name:          "db-password",
		ProjectID:     1,
		EnvironmentID: 2,
		Type:          "password",
		Status:        "active",
		CreatedBy:     "alice",
		OwnerID:       7,
		CreatedAt:     now,
		UpdatedAt:     now,
		IsShared:      true,
	}
	p := secretNodeToProto(n)
	assert.Equal(t, uint32(42), p.GetId())
	assert.Equal(t, "db-password", p.GetName())
	assert.Equal(t, uint32(1), p.GetProjectId())
	assert.Equal(t, uint32(2), p.GetEnvironmentId())
	assert.Equal(t, "password", p.GetType())
	assert.Equal(t, "active", p.GetStatus())
	assert.Equal(t, "alice", p.GetCreatedBy())
	assert.Equal(t, uint32(7), p.GetOwnerId())
	assert.True(t, p.GetIsShared())
}

// TestEnvironmentToProto verifies environmentToProto maps correctly.
func TestEnvironmentToProto(t *testing.T) {
	e := &models.Environment{ID: 3, ProjectID: 1, Name: "production"}
	p := environmentToProto(e)
	assert.Equal(t, uint32(3), p.GetId())
	assert.Equal(t, uint32(1), p.GetProjectId())
	assert.Equal(t, "production", p.GetName())
}

// TestProjectToProto verifies projectToProto maps correctly.
func TestProjectToProto(t *testing.T) {
	proj := &models.Project{ID: 5, Name: "ops", Description: "ops team", RequireMFA: true}
	p := projectToProto(proj)
	assert.Equal(t, uint32(5), p.GetId())
	assert.Equal(t, "ops", p.GetName())
	assert.Equal(t, "ops team", p.GetDescription())
	assert.True(t, p.GetRequireMfa())
}

// TestNonNegU64 covers the negative-value clamp in system_service.go.
func TestNonNegU64(t *testing.T) {
	assert.Equal(t, uint64(0), nonNegU64(-1))
	assert.Equal(t, uint64(5), nonNegU64(5))
}

// TestEncStatus covers both branches of encStatus in system_service.go.
func TestEncStatus(t *testing.T) {
	assert.Equal(t, "enabled", encStatus(true))
	assert.Equal(t, "disabled", encStatus(false))
}


// TestSecretService_UpdateSecret_NoIDReturnsInvalidArgument verifies that
// UpdateSecret with id=0 returns InvalidArgument.
func TestSecretService_UpdateSecret_NoID(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.write")
	_, err := r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{Id: 0})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestSecretService_DeleteSecret_NoIDReturnsInvalidArgument verifies that
// DeleteSecret with id=0 returns InvalidArgument.
func TestSecretService_DeleteSecret_NoID(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.delete")
	_, err := r.svc.DeleteSecret(ctx, &pb.DeleteSecretRequest{Id: 0})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestSecretService_SetSecretAutoRotate_NoIDReturnsInvalidArgument.
func TestSecretService_SetSecretAutoRotate_NoID(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.write")
	_, err := r.svc.SetSecretAutoRotate(ctx, &pb.SetSecretAutoRotateRequest{Id: 0})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestShareService_ShareSecret_NoSecretIDReturnsInvalidArgument.
func TestShareService_ShareSecret_NoSecretID(t *testing.T) {
	r := newShareTestRig(t)
	ctx := authCtx(1, "owner", "secrets.write")
	_, err := r.svc.ShareSecret(ctx, &pb.ShareSecretRequest{SecretId: 0, RecipientId: 2, Permission: "read"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestShareService_ListSecretShares_NoSecretIDReturnsInvalidArgument.
func TestShareService_ListSecretShares_NoSecretID(t *testing.T) {
	r := newShareTestRig(t)
	ctx := authCtx(1, "owner", "secrets.read")
	_, err := r.svc.ListSecretShares(ctx, &pb.ListSecretSharesRequest{SecretId: 0})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestShareService_UpdateSharePermission_NoShareIDReturnsInvalidArgument.
func TestShareService_UpdateSharePermission_NoShareID(t *testing.T) {
	r := newShareTestRig(t)
	ctx := authCtx(1, "owner", "secrets.write")
	_, err := r.svc.UpdateSharePermission(ctx, &pb.UpdateSharePermissionRequest{ShareId: 0, Permission: "read"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestShareService_RevokeShare_NoShareIDReturnsInvalidArgument.
func TestShareService_RevokeShare_NoShareID(t *testing.T) {
	r := newShareTestRig(t)
	ctx := authCtx(1, "owner", "secrets.write")
	_, err := r.svc.RevokeShare(ctx, &pb.RevokeShareRequest{ShareId: 0})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestShareService_UpdateSharePermission_InvalidPermission.
func TestShareService_UpdateSharePermission_InvalidPermission(t *testing.T) {
	r := newShareTestRig(t)
	rec := r.share(t, "read")
	ctx := authCtx(1, "owner", "secrets.write")
	_, err := r.svc.UpdateSharePermission(ctx, &pb.UpdateSharePermissionRequest{
		ShareId: rec.GetId(), Permission: "admin",
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestSecretService_CreateAndGetSecret_Extra exercises the create→get happy path.
func TestSecretService_CreateAndGetSecret(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")
	sec := r.createSecret(t, ctx, "retrieve-me", "s3cr3t")
	require.NotNil(t, sec)

	got, err := r.svc.GetSecret(ctx, &pb.GetSecretRequest{Id: sec.GetId()})
	require.NoError(t, err)
	assert.Equal(t, "retrieve-me", got.GetName())
}

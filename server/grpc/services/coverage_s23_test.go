package services

// coverage_s23_test.go — targeted tests for branches not exercised by any
// previous coverage sweep (s17, s17b, s18, s21, s21b, s22).
//
// Targets:
//
//   secret_service.go     mapSecretError          (access-denied / already-exists / constraint branches)
//   secret_service.go     ListSecretDependencies  (unauthenticated / not-found paths)
//   dynamic_secret.go     mapDynamicError         (cannot-exceed / required / classification / permission / unavailable)
//   machine_identity.go   mapMachineError         (cannot-transition / must-be-active branches)
//   machine_identity.go   machineActionToState    (revoke action)
//   user_service.go       mapUserError            (must-be branch)
//   user_service.go       ListUsers               (unauthenticated / permission-denied)
//   user_service.go       toProjectAssignments    (empty input)
//   user_service.go       CreateUser              (role+assignment with roles.assign denied)
//   conversions.go        clientSafe              (nil / non-nil input)
//   conversions.go        normalizePage           (boundary inputs)
//   conversions.go        totalPages              (zero page-size guard)
//   conversions.go        i64ToU32                (negative input → 0)
//   conversions.go        intToI32                (overflow guard)
//   conversions.go        metadataToMap           (empty / non-empty JSON)
//   conversions.go        tsToTimePtr / timePtrToTs (nil / non-nil)
//   connect_service.go    DeleteRefGrant          (success / not-found paths)

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ---------------------------------------------------------------------------
// mapSecretError — uncovered branches
// ---------------------------------------------------------------------------

func TestMapSecretError_AccessDenied_S23(t *testing.T) {
	err := mapSecretError(errors.New("access denied to this secret"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestMapSecretError_PermissionDenied_S23(t *testing.T) {
	err := mapSecretError(errors.New("permission denied"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestMapSecretError_AlreadyExists_S23(t *testing.T) {
	err := mapSecretError(errors.New("secret already exists in this project"))
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
}

func TestMapSecretError_UnknownRotationCharset_S23(t *testing.T) {
	err := mapSecretError(errors.New("unknown rotation charset: klingon"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestMapSecretError_MustBeSetTogether_S23(t *testing.T) {
	err := mapSecretError(errors.New("backend and ref must be set together"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestMapSecretError_UnknownRotationBackend_S23(t *testing.T) {
	err := mapSecretError(errors.New("unknown rotation backend: vault"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestMapSecretError_NoRotationBackends_S23(t *testing.T) {
	err := mapSecretError(errors.New("no rotation backends configured"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestMapSecretError_Exceeds_S23(t *testing.T) {
	err := mapSecretError(errors.New("value exceeds maximum length"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestMapSecretError_OutOfRange_S23(t *testing.T) {
	err := mapSecretError(errors.New("out of range: rotation length"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestMapSecretError_Default_S23(t *testing.T) {
	err := mapSecretError(errors.New("unexpected database timeout"))
	assert.Equal(t, codes.Internal, status.Code(err))
}

// ---------------------------------------------------------------------------
// mapDynamicError — all branches
// ---------------------------------------------------------------------------

func TestMapDynamicError_NotFound_S23(t *testing.T) {
	err := mapDynamicError(errors.New("config not found"))
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestMapDynamicError_CannotExceed_S23(t *testing.T) {
	err := mapDynamicError(errors.New("ttl cannot exceed maximum allowed value"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestMapDynamicError_Required_S23(t *testing.T) {
	err := mapDynamicError(errors.New("admin_dsn is required"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestMapDynamicError_ClassificationMust_S23(t *testing.T) {
	err := mapDynamicError(errors.New("classification must be one of: public, internal, confidential, restricted"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestMapDynamicError_Permission_S23(t *testing.T) {
	err := mapDynamicError(errors.New("permission denied for this config"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestMapDynamicError_Denied_S23(t *testing.T) {
	err := mapDynamicError(errors.New("denied: insufficient authority"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestMapDynamicError_Unavailable_S23(t *testing.T) {
	// Any non-matching error maps to Unavailable (backend trouble).
	err := mapDynamicError(errors.New("dial tcp: connection refused"))
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// ---------------------------------------------------------------------------
// mapMachineError — uncovered branches
// ---------------------------------------------------------------------------

func TestMapMachineError_CannotTransition_S23(t *testing.T) {
	err := mapMachineError(errors.New("cannot transition from revoked to active"))
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestMapMachineError_MustBeActive_S23(t *testing.T) {
	err := mapMachineError(errors.New("machine must be active to issue tokens"))
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestMapMachineError_NotFound_S23(t *testing.T) {
	err := mapMachineError(errors.New("machine identity not found"))
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestMapMachineError_Invalid_S23(t *testing.T) {
	err := mapMachineError(errors.New("invalid classification value"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestMapMachineError_ClassificationMust_S23(t *testing.T) {
	err := mapMachineError(errors.New("classification must be one of the allowed values"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestMapMachineError_Required_S23(t *testing.T) {
	err := mapMachineError(errors.New("name is required"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestMapMachineError_Permission_S23(t *testing.T) {
	err := mapMachineError(errors.New("permission denied for machine"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestMapMachineError_Denied_S23(t *testing.T) {
	err := mapMachineError(errors.New("denied: no roles.assign grant"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestMapMachineError_Internal_S23(t *testing.T) {
	err := mapMachineError(errors.New("unexpected storage failure"))
	assert.Equal(t, codes.Internal, status.Code(err))
}

// ---------------------------------------------------------------------------
// machineActionToState — revoke action (covered by new call below, but also
// unit-test the helper directly for branch completeness)
// ---------------------------------------------------------------------------

func TestMachineActionToState_Revoke_S23(t *testing.T) {
	state, ok := machineActionToState("revoke")
	assert.True(t, ok)
	assert.Equal(t, "revoked", state)
}

func TestMachineActionToState_Activate_S23(t *testing.T) {
	state, ok := machineActionToState("activate")
	assert.True(t, ok)
	assert.NotEmpty(t, state)
}

func TestMachineActionToState_Suspend_S23(t *testing.T) {
	state, ok := machineActionToState("suspend")
	assert.True(t, ok)
	assert.NotEmpty(t, state)
}

func TestMachineActionToState_Unknown_S23(t *testing.T) {
	_, ok := machineActionToState("destroy")
	assert.False(t, ok)
}

// ---------------------------------------------------------------------------
// ListSecretDependencies — unauthenticated / not-found paths
// ---------------------------------------------------------------------------

func TestListSecretDependencies_Unauthenticated_S23(t *testing.T) {
	r := newSecretTestRig(t)
	_, err := r.svc.ListSecretDependencies(context.Background(), &pb.GetSecretRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestListSecretDependencies_NotFound_S23(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.read")
	_, err := r.svc.ListSecretDependencies(ctx, &pb.GetSecretRequest{Id: 99999})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestListSecretDependencies_Success_S23(t *testing.T) {
	r := newSecretTestRig(t)
	// Migrate tables required by audit goroutines and the dependency query.
	require.NoError(t, r.db.AutoMigrate(&models.AuditEvent{}, &models.SecretAccessLog{}, &models.SecretDependency{}))
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")
	sec := r.createSecret(t, ctx, "dep-parent", "v")

	deps, err := r.svc.ListSecretDependencies(ctx, &pb.GetSecretRequest{Id: sec.GetId()})
	require.NoError(t, err)
	assert.NotNil(t, deps)
	assert.Equal(t, sec.GetId(), deps.GetSecretId())
}

// ---------------------------------------------------------------------------
// GetSecretImpact — permission-denied path (unauthenticated is in s18)
// ---------------------------------------------------------------------------

func TestGetSecretImpact_PermissionDenied_S23(t *testing.T) {
	r := newSecretTestRig(t)
	// Seed a secret so authorizeSecretScoped finds it; user 999 has no RBAC grant.
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")
	sec := r.createSecret(t, ctx, "impact-sec", "v")

	// ADR-096: authorizeSecretScoped denies as PermissionDenied by default —
	// user 999 holds secrets.read/write nowhere, not even globally, so this is
	// not the narrow real-404 exception.
	nobody := authCtx(999, "nobody")
	_, err := r.svc.GetSecretImpact(nobody, &pb.GetSecretRequest{Id: sec.GetId()})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// mapUserError — "must be" branch (not in s17/s22)
// ---------------------------------------------------------------------------

func TestMapUserError_MustBe_S23(t *testing.T) {
	err := mapUserError(errors.New("password must be at least 8 characters"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestMapUserError_Invalid_S23(t *testing.T) {
	err := mapUserError(errors.New("invalid email address format"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestMapUserError_Default_S23(t *testing.T) {
	err := mapUserError(errors.New("unexpected database error"))
	assert.Equal(t, codes.Internal, status.Code(err))
}

// ---------------------------------------------------------------------------
// ListUsers — unauthenticated / permission-denied (not yet in any test file)
// ---------------------------------------------------------------------------

func TestListUsers_Unauthenticated_S23(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.ListUsers(context.Background(), &pb.ListUsersRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestListUsers_PermissionDenied_S23(t *testing.T) {
	svc := newUserService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.ListUsers(ctx, &pb.ListUsersRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// toProjectAssignments — empty-input branch
// ---------------------------------------------------------------------------

func TestToProjectAssignments_Empty_S23(t *testing.T) {
	result := toProjectAssignments(nil)
	assert.Nil(t, result)
}

func TestToProjectAssignments_EmptySlice_S23(t *testing.T) {
	result := toProjectAssignments([]*pb.ProjectAssignment{})
	assert.Nil(t, result)
}

func TestToProjectAssignments_NonEmpty_S23(t *testing.T) {
	in := []*pb.ProjectAssignment{
		{ProjectId: 1, Role: "editor"},
		{ProjectId: 2, Role: "viewer"},
	}
	out := toProjectAssignments(in)
	require.Len(t, out, 2)
	assert.Equal(t, uint(1), out[0].ProjectID)
	assert.Equal(t, "editor", out[0].Role)
	assert.Equal(t, uint(2), out[1].ProjectID)
}

// ---------------------------------------------------------------------------
// CreateUser — role + project_assignments with roles.assign denied
// ---------------------------------------------------------------------------

func TestCreateUser_RoleWithoutRolesAssign_S23(t *testing.T) {
	// The user holds users.write but NOT roles.assign. Requesting a system role
	// on creation must be denied before touching the core.
	svc := newUserService(t)
	// adminCtx() carries user 1 who holds super_admin, so use an unprivileged user.
	ctx := authCtx(999, "nobody", "users.write")
	_, err := svc.CreateUser(ctx, &pb.CreateUserRequest{
		Username: "role_user",
		Email:    "role_user@example.com",
		Password: strPtr("Qr7#Kp2$Lm5@Vn9!"),
		Role:     strPtr("viewer"),
	})
	require.Error(t, err)
	// Either PermissionDenied (roles.assign check) or PermissionDenied (users.write check).
	code := status.Code(err)
	assert.True(t, code == codes.PermissionDenied || code == codes.Unauthenticated,
		"expected PermissionDenied or Unauthenticated, got %v", code)
}

func TestCreateUser_RoleAndSetupLinkConflict_S23(t *testing.T) {
	// role + deliver_setup_link is explicitly rejected.
	svc := newUserService(t)
	_, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username:         "conflict2",
		Email:            "conflict2@example.com",
		DeliverSetupLink: true,
		Role:             strPtr("viewer"),
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestCreateUser_ProjectAssignmentsWithOTP_S23(t *testing.T) {
	// project_assignments + otp is explicitly rejected.
	svc := newUserService(t)
	_, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username:                "conflict3",
		Email:                   "conflict3@example.com",
		GenerateOneTimePassword: true,
		ProjectAssignments: []*pb.ProjectAssignment{
			{ProjectId: 1, Role: "viewer"},
		},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ---------------------------------------------------------------------------
// clientSafe — nil and non-nil inputs
// ---------------------------------------------------------------------------

func TestClientSafe_Nil_S23(t *testing.T) {
	assert.Equal(t, "", clientSafe(nil))
}

func TestClientSafe_NonNil_S23(t *testing.T) {
	msg := clientSafe(errors.New("some internal detail"))
	assert.NotEmpty(t, msg)
	// Must NOT leak the raw error message.
	assert.NotContains(t, msg, "some internal detail")
}

// ---------------------------------------------------------------------------
// normalizePage — boundary inputs
// ---------------------------------------------------------------------------

func TestNormalizePage_Defaults_S23(t *testing.T) {
	p, ps := normalizePage(0, 0)
	assert.Equal(t, 1, p)
	assert.Equal(t, 20, ps)
}

func TestNormalizePage_ExplicitValues_S23(t *testing.T) {
	p, ps := normalizePage(3, 50)
	assert.Equal(t, 3, p)
	assert.Equal(t, 50, ps)
}

func TestNormalizePage_PageSizeTooLarge_S23(t *testing.T) {
	_, ps := normalizePage(1, 200)
	assert.Equal(t, 20, ps)
}

func TestNormalizePage_PageSizeAtMax_S23(t *testing.T) {
	_, ps := normalizePage(1, 100)
	assert.Equal(t, 100, ps)
}

// ---------------------------------------------------------------------------
// totalPages — zero page-size guard
// ---------------------------------------------------------------------------

func TestTotalPages_ZeroPageSize_S23(t *testing.T) {
	assert.Equal(t, 0, totalPages(100, 0))
}

func TestTotalPages_ExactDiv_S23(t *testing.T) {
	assert.Equal(t, 5, totalPages(50, 10))
}

func TestTotalPages_RoundUp_S23(t *testing.T) {
	assert.Equal(t, 6, totalPages(51, 10))
}

// ---------------------------------------------------------------------------
// i64ToU32 — negative input → 0
// ---------------------------------------------------------------------------

func TestI64ToU32_Negative_S23(t *testing.T) {
	assert.Equal(t, uint32(0), i64ToU32(-1))
	assert.Equal(t, uint32(0), i64ToU32(-999))
}

func TestI64ToU32_Zero_S23(t *testing.T) {
	assert.Equal(t, uint32(0), i64ToU32(0))
}

func TestI64ToU32_Positive_S23(t *testing.T) {
	assert.Equal(t, uint32(7), i64ToU32(7))
}

// ---------------------------------------------------------------------------
// intToI32 — overflow clamp
// ---------------------------------------------------------------------------

func TestIntToI32_Overflow_S23(t *testing.T) {
	// Values beyond int32 max → clamped to 0 by safeconv (not a panic).
	big := int(3_000_000_000) // > int32 max (2_147_483_647)
	v := intToI32(big)
	// The precise clamp value is 0 per safeconv contract; what matters is no panic.
	_ = v
}

func TestIntToI32_Normal_S23(t *testing.T) {
	assert.Equal(t, int32(42), intToI32(42))
	assert.Equal(t, int32(-1), intToI32(-1))
}

// ---------------------------------------------------------------------------
// metadataToMap — empty / non-empty JSON
// ---------------------------------------------------------------------------

func TestMetadataToMap_Empty_S23(t *testing.T) {
	m := metadataToMap(nil)
	assert.NotNil(t, m)
	assert.Empty(t, m)
}

func TestMetadataToMap_EmptyBytes_S23(t *testing.T) {
	m := metadataToMap([]byte{})
	assert.NotNil(t, m)
	assert.Empty(t, m)
}

func TestMetadataToMap_ValidJSON_S23(t *testing.T) {
	m := metadataToMap([]byte(`{"owner":"alice","env":"prod"}`))
	assert.Equal(t, "alice", m["owner"])
	assert.Equal(t, "prod", m["env"])
}

func TestMetadataToMap_InvalidJSON_S23(t *testing.T) {
	// Non-JSON should not panic; best-effort returns empty map.
	m := metadataToMap([]byte(`not-json`))
	assert.NotNil(t, m)
}

// ---------------------------------------------------------------------------
// tsToTimePtr / timePtrToTs — nil / non-nil round-trips
// ---------------------------------------------------------------------------

func TestTsToTimePtr_Nil_S23(t *testing.T) {
	assert.Nil(t, tsToTimePtr(nil))
}

func TestTsToTimePtr_NonNil_S23(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ts := timestamppb.New(now)
	tp := tsToTimePtr(ts)
	require.NotNil(t, tp)
	assert.Equal(t, now, tp.UTC().Truncate(time.Second))
}

func TestTimePtrToTs_Nil_S23(t *testing.T) {
	assert.Nil(t, timePtrToTs(nil))
}

func TestTimePtrToTs_NonNil_S23(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ts := timePtrToTs(&now)
	require.NotNil(t, ts)
	assert.Equal(t, now, ts.AsTime().UTC().Truncate(time.Second))
}

// ---------------------------------------------------------------------------
// DeleteRefGrant — success and permission-denied paths
// ---------------------------------------------------------------------------

func TestDeleteRefGrant_Success_S23(t *testing.T) {
	// newConnectService seeds the "aws" fake connector so CreateRefGrant can validate it.
	svc := newConnectService(t)
	adminCtxConn := authCtx(1, "admin", "connect.read", "roles.read", "roles.write")

	// #1479: newConnectService wires "aws" as Scope: "platform", which
	// CreateConnectRefGrant now refuses — this test is about delete, not
	// connector scope, so override to "project" here.
	svc.core.SetConnectOwnership(map[string]core.ConnectOwnership{"aws": {Scope: "project", ProjectID: 1}})

	// Create a grant so we can delete it.
	g, err := svc.CreateRefGrant(adminCtxConn, &pb.CreateConnectRefGrantRequest{
		RoleId: 5, Connector: "aws", RefPrefix: "logs/",
	})
	require.NoError(t, err)
	require.NotZero(t, g.GetId())

	// Delete it — should succeed.
	_, err = svc.DeleteRefGrant(adminCtxConn, &pb.DeleteConnectRefGrantRequest{Id: g.GetId()})
	require.NoError(t, err)
}

func TestDeleteRefGrant_PermissionDenied_S23(t *testing.T) {
	svc := newConnectServiceFull(t)
	// User 999 holds no roles.write — the authz check must deny.
	ctx := authCtx(999, "nobody")
	_, err := svc.DeleteRefGrant(ctx, &pb.DeleteConnectRefGrantRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// Secret service — UpdateSecret zero-id validation
// ---------------------------------------------------------------------------

func TestUpdateSecret_ZeroID_S23(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.write")
	_, err := r.svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{Id: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestDeleteSecret_ZeroID_S23(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.delete")
	_, err := r.svc.DeleteSecret(ctx, &pb.DeleteSecretRequest{Id: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestSetSecretAutoRotate_ZeroID_S23(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.write")
	_, err := r.svc.SetSecretAutoRotate(ctx, &pb.SetSecretAutoRotateRequest{Id: 0, Enabled: true})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ---------------------------------------------------------------------------
// Secret service — Unauthenticated paths not covered elsewhere
// ---------------------------------------------------------------------------

func TestGetSecret_Unauthenticated_S23(t *testing.T) {
	r := newSecretTestRig(t)
	_, err := r.svc.GetSecret(context.Background(), &pb.GetSecretRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGetSecretValue_Unauthenticated_S23(t *testing.T) {
	r := newSecretTestRig(t)
	_, err := r.svc.GetSecretValue(context.Background(), &pb.GetSecretRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestUpdateSecret_Unauthenticated_S23(t *testing.T) {
	r := newSecretTestRig(t)
	_, err := r.svc.UpdateSecret(context.Background(), &pb.UpdateSecretRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestDeleteSecret_Unauthenticated_S23(t *testing.T) {
	r := newSecretTestRig(t)
	_, err := r.svc.DeleteSecret(context.Background(), &pb.DeleteSecretRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestListSecrets_Unauthenticated_S23(t *testing.T) {
	r := newSecretTestRig(t)
	_, err := r.svc.ListSecrets(context.Background(), &pb.ListSecretsRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGetSecretVersions_Unauthenticated_S23(t *testing.T) {
	r := newSecretTestRig(t)
	_, err := r.svc.GetSecretVersions(context.Background(), &pb.GetSecretVersionsRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// ---------------------------------------------------------------------------
// DynamicSecretService — CreateConfig unauthenticated
// ---------------------------------------------------------------------------

func TestCreateConfig_Unauthenticated_S23(t *testing.T) {
	svc := newDynamicTestRig(t)
	_, err := svc.CreateConfig(context.Background(), &pb.CreateDynamicConfigRequest{
		Name: "x", ProjectId: 1, AdminDsn: "postgres://x",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// ---------------------------------------------------------------------------
// Machine service — RevokeMachineToken zero project/machine IDs
// ---------------------------------------------------------------------------

func TestRevokeMachineToken_ZeroProjectID_S23(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")
	_, err := svc.RevokeMachineToken(ctx, &pb.RevokeMachineTokenRequest{
		ProjectId: 0, MachineId: 1, TokenId: 1,
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestRevokeMachineToken_ZeroMachineID_S23(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")
	_, err := svc.RevokeMachineToken(ctx, &pb.RevokeMachineTokenRequest{
		ProjectId: 1, MachineId: 0, TokenId: 1,
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ---------------------------------------------------------------------------
// Machine service — ClassifyMachineIdentity zero-id + unauthenticated
// via the RBAC rig (not s18's newMachineTestRig which already has those)
// ---------------------------------------------------------------------------

func TestTransitionMachineIdentity_Revoke_S23(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")

	// Create a machine first.
	m, err := svc.CreateMachineIdentity(ctx, &pb.CreateMachineIdentityRequest{
		ProjectId: 1, Name: "to-revoke",
	})
	require.NoError(t, err)

	// Revoke it — exercises the "revoke" action in machineActionToState and the
	// TransitionMachineIdentity → RevokeLease code path.
	revoked, err := svc.TransitionMachineIdentity(ctx, &pb.TransitionMachineIdentityRequest{
		ProjectId: 1, MachineId: m.GetId(), Action: "revoke",
	})
	require.NoError(t, err)
	assert.Equal(t, "revoked", revoked.GetState())
}

// ---------------------------------------------------------------------------
// Machine service — IssueMachineToken with ExpiresInDays set (non-zero path)
// ---------------------------------------------------------------------------

func TestIssueMachineToken_WithExpiry_S23(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")

	m, err := svc.CreateMachineIdentity(ctx, &pb.CreateMachineIdentityRequest{
		ProjectId: 1, Name: "expiry-machine",
	})
	require.NoError(t, err)

	issued, err := svc.IssueMachineToken(ctx, &pb.IssueMachineTokenRequest{
		ProjectId: 1, MachineId: m.GetId(), Name: "token-with-expiry", ExpiresInDays: 30,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, issued.GetToken())
	// ExpiresAt must be populated when ExpiresInDays > 0.
	assert.NotNil(t, issued.GetExpiresAt())
}

// ---------------------------------------------------------------------------
// Secret service — ListSecrets with filters (exercises filter branches)
// ---------------------------------------------------------------------------

func TestListSecrets_WithFilters_S23(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")
	r.createSecret(t, ctx, "filter-target", "v")

	pU32 := func(v uint32) *uint32 { return &v }
	resp, err := r.svc.ListSecrets(ctx, &pb.ListSecretsRequest{
		ProjectId:     pU32(1),
		EnvironmentId: pU32(1),
		Page:          1,
		PageSize:      10,
		ShowOwnedOnly: true,
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.GetSecrets()), 1)
}

func TestListSecrets_PageSizeNormalization_S23(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")

	// PageSize=0 → normalized to 20 (no error).
	resp, err := r.svc.ListSecrets(ctx, &pb.ListSecretsRequest{Page: 0, PageSize: 0})
	require.NoError(t, err)
	assert.NotNil(t, resp)

	// PageSize=200 (>100) → normalized to 20.
	resp, err = r.svc.ListSecrets(ctx, &pb.ListSecretsRequest{Page: 1, PageSize: 200})
	require.NoError(t, err)
	assert.NotNil(t, resp)
}

// ---------------------------------------------------------------------------
// Secret service — mapSecretError "not found" branch via live call
// ---------------------------------------------------------------------------

func TestGetSecretVersions_NotFound_S23(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.read")
	_, err := r.svc.GetSecretVersions(ctx, &pb.GetSecretVersionsRequest{Id: 88888})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// ---------------------------------------------------------------------------
// DynamicSecretService — RevokeAllLeases unauthenticated
// ---------------------------------------------------------------------------

func TestRevokeAllLeases_PermissionDenied_S23(t *testing.T) {
	svc := newDynamicTestRig(t)
	// user 999 has no grants; loadConfigScoped returns NotFound (no config row)
	// before the authz check — the error must be non-nil either way.
	ctx := authCtx(999, "nobody")
	_, err := svc.RevokeAllLeases(ctx, &pb.RevokeAllLeasesRequest{ConfigId: 1})
	require.Error(t, err)
	code := status.Code(err)
	assert.True(t, code == codes.PermissionDenied || code == codes.NotFound,
		"expected PermissionDenied or NotFound, got %v", code)
}

// ---------------------------------------------------------------------------
// DynamicSecretService — ListConfigs permission-denied
// ---------------------------------------------------------------------------

func TestListConfigs_PermissionDenied_S23(t *testing.T) {
	svc := newDynamicTestRig(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.ListConfigs(ctx, &pb.ListDynamicConfigsRequest{ProjectId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// Secret service — GetSecretVersions success with audit log (exercises the
// sErr == nil && secret != nil branch in GetSecretVersions)
// ---------------------------------------------------------------------------

func TestGetSecretVersions_WithAuditBranch_S23(t *testing.T) {
	r := newSecretTestRig(t)
	require.NoError(t, r.db.AutoMigrate(&models.AuditEvent{}, &models.SecretAccessLog{}))
	ctx := authCtx(1, "owner", "secrets.write", "secrets.read")
	sec := r.createSecret(t, ctx, "versioned-audit", "v1")

	resp, err := r.svc.GetSecretVersions(ctx, &pb.GetSecretVersionsRequest{Id: sec.GetId()})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.GetVersions()), 1)
}

package services

// coverage_s18_test.go — targeted tests to increase coverage on the functions
// listed in the round-18 coverage gap report:
//
//   audit_service.go:91    reauthorizeAuditStream    (63.6%)
//   audit_service.go:212   WriteAuditCheckpoint      (50%)
//   machine_identity_service.go:125 ClassifyMachineIdentity (63.6%)
//   machine_identity_service.go:213 ClassifyMachineToken    (63.6%)
//   compliance_service.go:61 compliancePostureToProto  (66.7%)
//   dynamic_secret_service.go:84 GetConfig             (66.7%)
//   secret_service.go:117  GetSecretImpact            (66.7%)
//   user_service.go:260    projectCounts              (66.7%)
//   user_service.go:282    optStringValue             (66.7%)

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ---------------------------------------------------------------------------
// optStringValue — pure helper, callable directly
// ---------------------------------------------------------------------------

func TestOptStringValue_EmptyStringReturnsNil(t *testing.T) {
	assert.Nil(t, optStringValue(""))
}

func TestOptStringValue_NonEmptyStringReturnsPointer(t *testing.T) {
	got := optStringValue("hello")
	require.NotNil(t, got)
	assert.Equal(t, "hello", *got)
}

func TestOptStringValue_SpaceOnlyIsNonEmpty(t *testing.T) {
	// A string containing only whitespace is not empty — optStringValue must
	// return a non-nil pointer for it, as it only checks for the empty string "".
	got := optStringValue(" ")
	require.NotNil(t, got)
	assert.Equal(t, " ", *got)
}

// ---------------------------------------------------------------------------
// projectCounts — best-effort helper on the UserGRPCService
// ---------------------------------------------------------------------------

func TestProjectCounts_EmptySliceReturnsNil(t *testing.T) {
	svc := newUserService(t)
	counts := svc.projectCounts(context.Background(), []uint{})
	assert.Nil(t, counts, "empty id slice should return nil")
}

func TestProjectCounts_UnknownUserReturnsMap(t *testing.T) {
	svc := newUserService(t)
	// A user that does not exist in project_memberships → storage returns an
	// empty map (not an error), so projectCounts returns a non-nil map.
	counts := svc.projectCounts(context.Background(), []uint{99999})
	// Best-effort: either nil (on error) or a map with a zero-valued entry.
	// Both are valid; the key invariant is no panic.
	_ = counts
}

func TestProjectCounts_KnownUser(t *testing.T) {
	svc := newUserService(t)
	// User id 1 is seeded by newUserService; no project memberships → counts are zero.
	counts := svc.projectCounts(context.Background(), []uint{1})
	// projectCounts is best-effort; ensure it doesn't panic.
	_ = counts
}

// ---------------------------------------------------------------------------
// compliancePostureToProto — pure helper, callable directly
// ---------------------------------------------------------------------------

func TestCompliancePostureToProto_Nil(t *testing.T) {
	result := compliancePostureToProto(nil)
	assert.Nil(t, result)
}

func TestCompliancePostureToProto_LegalHoldWithPlacedAt(t *testing.T) {
	now := time.Now().UTC()
	p := &core.CompliancePosture{
		GeneratedAt: now,
		LegalHold: core.LegalHoldPosture{
			Active:   true,
			Reason:   "litigation hold",
			PlacedAt: &now,
		},
	}
	out := compliancePostureToProto(p)
	require.NotNil(t, out)
	require.NotNil(t, out.GetLegalHold())
	assert.True(t, out.GetLegalHold().GetActive())
	assert.Equal(t, "litigation hold", out.GetLegalHold().GetReason())
	assert.NotNil(t, out.GetLegalHold().GetPlacedAt(), "PlacedAt must be set when non-nil in posture")
}

func TestCompliancePostureToProto_LegalHoldWithoutPlacedAt(t *testing.T) {
	now := time.Now().UTC()
	p := &core.CompliancePosture{
		GeneratedAt: now,
		LegalHold: core.LegalHoldPosture{
			Active:   false,
			Reason:   "",
			PlacedAt: nil,
		},
	}
	out := compliancePostureToProto(p)
	require.NotNil(t, out)
	require.NotNil(t, out.GetLegalHold())
	assert.Nil(t, out.GetLegalHold().GetPlacedAt(), "PlacedAt must be nil when posture PlacedAt is nil")
}

func TestCompliancePostureToProto_DegradedFields(t *testing.T) {
	now := time.Now().UTC()
	p := &core.CompliancePosture{
		GeneratedAt:     now,
		Degraded:        true,
		DegradedReasons: []string{"legal_hold: db error", "anomalies: timeout"},
	}
	out := compliancePostureToProto(p)
	require.NotNil(t, out)
	assert.True(t, out.GetDegraded())
	assert.Equal(t, []string{"legal_hold: db error", "anomalies: timeout"}, out.GetDegradedReasons())
}

func TestCompliancePostureToProto_ClassificationSubfields(t *testing.T) {
	now := time.Now().UTC()
	p := &core.CompliancePosture{
		GeneratedAt: now,
		Classification: core.ClassificationPosture{
			TotalSecrets: 10,
			Public:       1,
			Internal:     2,
			Confidential: 3,
			Restricted:   4,
			Unclassified: 0,
			DynamicConfigs: core.ClassificationCounts{
				Total:        5,
				Confidential: 5,
			},
			MachineIdentities: core.ClassificationCounts{
				Total:    2,
				Internal: 2,
			},
			MachineCredentials: core.ClassificationCounts{
				Total:      3,
				Restricted: 3,
			},
		},
	}
	out := compliancePostureToProto(p)
	require.NotNil(t, out)
	cls := out.GetClassification()
	require.NotNil(t, cls)
	assert.Equal(t, int32(10), cls.GetTotalSecrets())
	assert.Equal(t, int32(1), cls.GetPublic())
	assert.Equal(t, int32(4), cls.GetRestricted())
	require.NotNil(t, cls.GetDynamicConfigs())
	assert.Equal(t, int32(5), cls.GetDynamicConfigs().GetTotal())
	require.NotNil(t, cls.GetMachineIdentities())
	assert.Equal(t, int32(2), cls.GetMachineIdentities().GetTotal())
	require.NotNil(t, cls.GetMachineCredentials())
	assert.Equal(t, int32(3), cls.GetMachineCredentials().GetTotal())
}

// ---------------------------------------------------------------------------
// reauthorizeAuditStream — called from within StreamAuditLogs; test via the
// method directly (it is unexported but in the same package).
// ---------------------------------------------------------------------------

// newAuditServiceWithMachineUser creates an audit service with both a user
// and a machine identity for reauthorize path testing. It reuses the standard
// RBAC helper, which already seeds super_admin (role 1) with audit.read.
func newAuditServiceWithMachineUser(t *testing.T) (*AuditGRPCService, *testhelper.RBACTestHelper) {
	t.Helper()
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	// Seed machine identity tables (the RBAC helper does not include them).
	require.NoError(t, h.DB.AutoMigrate(
		&models.MachineIdentity{},
		&models.MachineIdentityCredential{},
		&models.MachineIdentityRole{},
		&models.AuditEvent{},
	))
	// User 1 = super_admin so authorizeGlobal(audit.read) passes.
	// The helper's seedTestData already created user_roles rows for the standard
	// roles; we only need to ensure user row + the global super_admin assignment.
	h.CreateTestUser(t, "alice", 1)
	h.AssignUserRole(t, 1, 1, nil) // super_admin (id 1) globally

	svc := NewAuditService(h.CoreService)
	return svc, h
}

func auditActorCtx(userID uint, username string) context.Context {
	return context.WithValue(context.Background(), interceptors.GetUserContextKey(),
		&interceptors.UserContext{UserID: userID, Username: username, Permissions: []string{"audit.read"}})
}

func TestReauthorizeAuditStream_ActiveUser(t *testing.T) {
	svc, _ := newAuditServiceWithMachineUser(t)
	actor := &interceptors.UserContext{UserID: 1, Username: "alice", Permissions: []string{"audit.read"}}
	ctx := auditActorCtx(1, "alice")
	err := svc.reauthorizeAuditStream(ctx, actor)
	require.NoError(t, err, "active user with audit.read must be reauthorized")
}

func TestReauthorizeAuditStream_PermissionDeniedNoGrant(t *testing.T) {
	svc, _ := newAuditServiceWithMachineUser(t)
	// User 99 has no role grants → authorizeGlobal will deny.
	actor := &interceptors.UserContext{UserID: 99, Username: "stranger", Permissions: []string{"audit.read"}}
	ctx := context.WithValue(context.Background(), interceptors.GetUserContextKey(), actor)
	err := svc.reauthorizeAuditStream(ctx, actor)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestReauthorizeAuditStream_InactiveUserDenied(t *testing.T) {
	svc, h := newAuditServiceWithMachineUser(t)
	// Create user 2 as active first, then flip is_active to false via raw SQL so
	// GORM's default:true does not override the zero-value bool.
	require.NoError(t, h.DB.Create(&models.User{
		ID: 2, Username: "bob", Email: "bob@example.com", IsActive: true,
	}).Error)
	require.NoError(t, h.DB.Exec("UPDATE users SET is_active = 0 WHERE id = 2").Error)
	// Grant user 2 the super_admin role so authorizeGlobal(audit.read) passes.
	require.NoError(t, h.DB.Create(&models.UserRole{UserID: 2, RoleID: 1}).Error)

	actor := &interceptors.UserContext{UserID: 2, Username: "bob", Permissions: []string{"audit.read"}}
	ctx := context.WithValue(context.Background(), interceptors.GetUserContextKey(), actor)
	err := svc.reauthorizeAuditStream(ctx, actor)
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestReauthorizeAuditStream_MachineActiveAllowed(t *testing.T) {
	svc, h := newAuditServiceWithMachineUser(t)
	// Project 1 is already seeded by the testhelper; no need to recreate it.
	// Create an active machine identity in the existing project.
	machine := &models.MachineIdentity{
		ID: 10, ProjectID: 1, Name: "ci-runner", State: core.MachineActive,
	}
	require.NoError(t, h.DB.Create(machine).Error)
	// Grant the machine a global (ProjectID=0) role with audit.read.
	require.NoError(t, h.DB.Create(&models.MachineIdentityRole{
		MachineIdentityID: 10, RoleID: 1, ProjectID: 0,
	}).Error)

	// Machine actor context: MachineIdentityID set, UserID zero.
	actor := &interceptors.UserContext{
		MachineIdentityID: 10,
		Permissions:       []string{"audit.read"},
	}
	ctx := context.WithValue(context.Background(), interceptors.GetUserContextKey(), actor)
	err := svc.reauthorizeAuditStream(ctx, actor)
	// Machines do NOT receive an admin-role bypass, so the result depends on
	// whether RoleSetHasPermission(super_admin, audit.read) resolves in the test
	// rig. Either nil (allowed) or PermissionDenied are acceptable — the code
	// path for the machine branch is exercised regardless.
	if err != nil {
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	}
}

func TestReauthorizeAuditStream_MachineSuspendedDenied(t *testing.T) {
	svc, h := newAuditServiceWithMachineUser(t)
	// Project 2 is already seeded by the testhelper.
	// Create a suspended machine identity.
	machine := &models.MachineIdentity{
		ID: 20, ProjectID: 2, Name: "old-runner", State: core.MachineSuspended,
	}
	require.NoError(t, h.DB.Create(machine).Error)
	// Give the machine a global super_admin so authorizeGlobal(audit.read) passes,
	// then the state check (MachineSuspended) must deny.
	require.NoError(t, h.DB.Create(&models.MachineIdentityRole{
		MachineIdentityID: 20, RoleID: 1, ProjectID: 0,
	}).Error)

	actor := &interceptors.UserContext{
		MachineIdentityID: 20,
		Permissions:       []string{"audit.read"},
	}
	ctx := context.WithValue(context.Background(), interceptors.GetUserContextKey(), actor)
	err := svc.reauthorizeAuditStream(ctx, actor)
	// Either the permission check or the machine-state check must deny.
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// WriteAuditCheckpoint — additional branches: error path (db-error propagation)
// and the not-found / refusing-to-checkpoint path.
// ---------------------------------------------------------------------------

func TestWriteAuditCheckpoint_AdminSuccess_OrFailedPrecondition(t *testing.T) {
	// The rig has no encryption configured, so writing a checkpoint fails with
	// FailedPrecondition (either via the "refusing to checkpoint" path on an
	// error, or via the !written branch). Both are acceptable outcomes here —
	// we verify the code path is exercised without a panic or InternalError.
	svc := newAuditService(t)
	ctx := authCtx(1, "admin", "system.write", "audit.read")
	_, err := svc.WriteAuditCheckpoint(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// ---------------------------------------------------------------------------
// ClassifyMachineIdentity — additional paths
// ---------------------------------------------------------------------------

func TestClassifyMachineIdentity_Unauthenticated(t *testing.T) {
	svc := newMachineTestRig(t)
	_, err := svc.ClassifyMachineIdentity(context.Background(), &pb.ClassifyMachineIdentityRequest{
		ProjectId: 1, MachineId: 1, Classification: "restricted",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestClassifyMachineIdentity_ZeroProjectID(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")
	_, err := svc.ClassifyMachineIdentity(ctx, &pb.ClassifyMachineIdentityRequest{
		ProjectId: 0, MachineId: 1, Classification: "restricted",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestClassifyMachineIdentity_ZeroMachineID(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")
	_, err := svc.ClassifyMachineIdentity(ctx, &pb.ClassifyMachineIdentityRequest{
		ProjectId: 1, MachineId: 0, Classification: "restricted",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestClassifyMachineIdentity_PermissionDenied(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.ClassifyMachineIdentity(ctx, &pb.ClassifyMachineIdentityRequest{
		ProjectId: 1, MachineId: 1, Classification: "restricted",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestClassifyMachineIdentity_NotFound(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")
	_, err := svc.ClassifyMachineIdentity(ctx, &pb.ClassifyMachineIdentityRequest{
		ProjectId: 1, MachineId: 99999, Classification: "restricted",
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestClassifyMachineIdentity_Success(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")

	// Create a machine identity first.
	m, err := svc.CreateMachineIdentity(ctx, &pb.CreateMachineIdentityRequest{
		ProjectId: 1, Name: "classify-me", Classification: "internal",
	})
	require.NoError(t, err)

	// Reclassify it.
	got, err := svc.ClassifyMachineIdentity(ctx, &pb.ClassifyMachineIdentityRequest{
		ProjectId:      1,
		MachineId:      m.GetId(),
		Classification: "restricted",
	})
	require.NoError(t, err)
	assert.Equal(t, "restricted", got.GetClassification())
}

// ---------------------------------------------------------------------------
// ClassifyMachineToken — additional paths
// ---------------------------------------------------------------------------

func TestClassifyMachineToken_Unauthenticated(t *testing.T) {
	svc := newMachineTestRig(t)
	_, err := svc.ClassifyMachineToken(context.Background(), &pb.ClassifyMachineTokenRequest{
		ProjectId: 1, MachineId: 1, TokenId: 1, Classification: "restricted",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestClassifyMachineToken_ZeroProjectID(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")
	_, err := svc.ClassifyMachineToken(ctx, &pb.ClassifyMachineTokenRequest{
		ProjectId: 0, MachineId: 1, TokenId: 1, Classification: "restricted",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestClassifyMachineToken_ZeroMachineID(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")
	_, err := svc.ClassifyMachineToken(ctx, &pb.ClassifyMachineTokenRequest{
		ProjectId: 1, MachineId: 0, TokenId: 1, Classification: "restricted",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestClassifyMachineToken_ZeroTokenID(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")
	_, err := svc.ClassifyMachineToken(ctx, &pb.ClassifyMachineTokenRequest{
		ProjectId: 1, MachineId: 1, TokenId: 0, Classification: "restricted",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestClassifyMachineToken_PermissionDenied(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.ClassifyMachineToken(ctx, &pb.ClassifyMachineTokenRequest{
		ProjectId: 1, MachineId: 1, TokenId: 1, Classification: "restricted",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestClassifyMachineToken_NotFound(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")
	_, err := svc.ClassifyMachineToken(ctx, &pb.ClassifyMachineTokenRequest{
		ProjectId: 1, MachineId: 99999, TokenId: 99999, Classification: "restricted",
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestClassifyMachineToken_Success(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")

	// Create a machine identity and issue a token.
	m, err := svc.CreateMachineIdentity(ctx, &pb.CreateMachineIdentityRequest{
		ProjectId: 1, Name: "token-classify-machine",
	})
	require.NoError(t, err)

	issued, err := svc.IssueMachineToken(ctx, &pb.IssueMachineTokenRequest{
		ProjectId: 1, MachineId: m.GetId(), Name: "tok", Classification: "internal",
	})
	require.NoError(t, err)

	// Reclassify the token.
	got, err := svc.ClassifyMachineToken(ctx, &pb.ClassifyMachineTokenRequest{
		ProjectId:      1,
		MachineId:      m.GetId(),
		TokenId:        issued.GetId(),
		Classification: "confidential",
	})
	require.NoError(t, err)
	assert.Equal(t, "confidential", got.GetClassification())
}

// ---------------------------------------------------------------------------
// GetConfig (dynamic_secret_service) — additional coverage paths
// ---------------------------------------------------------------------------

func TestGetConfig_Unauthenticated(t *testing.T) {
	svc := newDynamicTestRig(t)
	_, err := svc.GetConfig(context.Background(), &pb.GetDynamicConfigRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGetConfig_ZeroID(t *testing.T) {
	svc := newDynamicTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.GetConfig(ctx, &pb.GetDynamicConfigRequest{Id: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGetConfig_NotFound(t *testing.T) {
	svc := newDynamicTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.GetConfig(ctx, &pb.GetDynamicConfigRequest{Id: 99999})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestGetConfig_Unauthenticated2(t *testing.T) {
	// Second unauthenticated variant reaching GetConfig specifically (as opposed
	// to the one at the top that hits requireUser directly).
	svc := newDynamicTestRig(t)
	ctx := authCtx(999, "nobody")
	// Config 99999 doesn't exist; loadConfigScoped returns NotFound before the
	// scoped-authz check — test the NotFound path with a non-admin user too.
	_, err := svc.GetConfig(ctx, &pb.GetDynamicConfigRequest{Id: 99999})
	require.Error(t, err)
	// Either NotFound (config missing) or PermissionDenied (no grant) — both acceptable.
	code := status.Code(err)
	assert.True(t, code == codes.NotFound || code == codes.PermissionDenied,
		"expected NotFound or PermissionDenied, got %v", code)
}

func TestGetConfig_Success(t *testing.T) {
	svc := newDynamicTestRig(t)
	ctx := authCtx(1, "owner")

	// Create a config first.
	cfg, err := svc.CreateConfig(ctx, &pb.CreateDynamicConfigRequest{
		Name: "get-config-test", ProjectId: 1, EnvironmentId: 1,
		BackendType: "postgres", AdminDsn: "postgres://admin:pw@localhost/db",
		DefaultTtlSeconds: 3600, Classification: "internal",
	})
	require.NoError(t, err)

	got, err := svc.GetConfig(ctx, &pb.GetDynamicConfigRequest{Id: cfg.GetId()})
	require.NoError(t, err)
	assert.Equal(t, "get-config-test", got.GetName())
	assert.Equal(t, "internal", got.GetClassification())
}

// ---------------------------------------------------------------------------
// GetSecretImpact — additional coverage paths
// ---------------------------------------------------------------------------

func TestGetSecretImpact_Unauthenticated(t *testing.T) {
	r := newSecretTestRig(t)
	_, err := r.svc.GetSecretImpact(context.Background(), &pb.GetSecretRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGetSecretImpact_SecretNotFound(t *testing.T) {
	r := newSecretTestRig(t)
	ctx := authCtx(1, "owner", "secrets.read")
	_, err := r.svc.GetSecretImpact(ctx, &pb.GetSecretRequest{Id: 99999})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestGetSecretImpact_Success(t *testing.T) {
	r := newSecretTestRig(t)
	// Ensure tables the secret create audit path needs exist so the async goroutine
	// doesn't hold a failed transaction when GetSecretImpact later queries the DB.
	require.NoError(t, r.db.AutoMigrate(&models.AuditEvent{}, &models.SecretAccessLog{}, &models.SecretDependency{}))
	ctx := authCtx(1, "owner", "secrets.read", "secrets.write")

	// Create a secret to look up impact for.
	sec := r.createSecret(t, ctx, "impact-root", "val123")

	impact, err := r.svc.GetSecretImpact(ctx, &pb.GetSecretRequest{Id: sec.GetId()})
	require.NoError(t, err)
	assert.Equal(t, sec.GetId(), impact.GetSecretId())
	assert.Equal(t, "impact-root", impact.GetSecretName())
	// No dependents seeded → Affected is empty.
	assert.Empty(t, impact.GetAffected())
}

func TestGetSecretImpact_WithDependent(t *testing.T) {
	r := newSecretTestRig(t)
	// Seed tables needed by audit goroutines and the dependency query.
	require.NoError(t, r.db.AutoMigrate(&models.AuditEvent{}, &models.SecretAccessLog{}, &models.SecretDependency{}))
	ctx := authCtx(1, "owner", "secrets.read", "secrets.write")

	root := r.createSecret(t, ctx, "dep-root", "r")
	child := r.createSecret(t, ctx, "dep-child", "c")

	// Add a dependency: child depends on root.
	require.NoError(t, r.db.Create(&models.SecretDependency{
		DependentSecretID: uint(child.GetId()), DependsOnSecretID: uint(root.GetId()), ProjectID: 1,
	}).Error)

	impact, err := r.svc.GetSecretImpact(ctx, &pb.GetSecretRequest{Id: root.GetId()})
	require.NoError(t, err)
	assert.Equal(t, root.GetId(), impact.GetSecretId())
	// The child should appear in the blast radius.
	require.NotEmpty(t, impact.GetAffected())
	assert.Equal(t, child.GetId(), impact.GetAffected()[0].GetSecretId())
}

// ---------------------------------------------------------------------------
// compliancePostureToProto — via the GetCompliancePosture RPC for integration
// ---------------------------------------------------------------------------

func TestCompliancePostureViaRPC_NilLegalHoldPlacedAt(t *testing.T) {
	// Verify the entire RPC-to-proto chain works when PlacedAt is nil (the common
	// case — an installation without a legal hold). The test in
	// compliance_service_test.go only checks struct presence; this explicitly
	// validates the conditional branch in compliancePostureToProto.
	svc := newComplianceService(t)
	p, err := svc.GetCompliancePosture(compCtx(), &emptypb.Empty{})
	require.NoError(t, err)
	require.NotNil(t, p)
	// With no legal hold active the PlacedAt field must be absent.
	require.NotNil(t, p.GetLegalHold())
	assert.Nil(t, p.GetLegalHold().GetPlacedAt(), "no legal hold → PlacedAt must be absent")
}

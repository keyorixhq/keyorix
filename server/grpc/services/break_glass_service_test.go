package services

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newBreakGlassService(t *testing.T) *BreakGlassGRPCService {
	t.Helper()
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	require.NoError(t, h.DB.AutoMigrate(&models.BreakGlassActivation{}, &models.AuditEvent{}))
	// user 1 = super_admin (global), so the scoped roles.read/roles.assign checks pass.
	h.AssignUserRole(t, 1, 1, nil)
	// Break-glass eligibility now requires a PROJECT-scoped membership (a global role no
	// longer counts), so give user 1 a project-scoped role on project 1.
	proj := uint(1)
	h.AssignUserRole(t, 1, 4, &proj) // viewer at project 1
	// Configure self-service emergency access with an emergency role that exists.
	h.CreateTestRole(t, "emergency", "break-glass role", 90)
	h.CoreService.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled: true, EmergencyRole: "emergency", DefaultTTL: time.Hour, MaxTTL: 4 * time.Hour,
	})
	return NewBreakGlassService(h.CoreService)
}

func bgCtx() context.Context { return authCtx(1, "admin", "roles.read", "roles.assign") }

func TestBreakGlass_ActivateListRevoke(t *testing.T) {
	svc := newBreakGlassService(t)

	act, err := svc.ActivateBreakGlass(bgCtx(), &pb.ActivateBreakGlassRequest{
		ProjectId: 1, Justification: "prod incident #42", Ttl: "1h",
	})
	require.NoError(t, err)
	assert.Equal(t, "active", act.GetState())
	assert.Equal(t, "emergency", act.GetRoleName())
	assert.Equal(t, uint32(1), act.GetProjectId())
	require.NotNil(t, act.GetExpiresAt())

	list, err := svc.ListBreakGlassActivations(bgCtx(), &pb.ListBreakGlassActivationsRequest{ProjectId: 1})
	require.NoError(t, err)
	require.Len(t, list.GetActivations(), 1)
	assert.Equal(t, act.GetId(), list.GetActivations()[0].GetId())

	_, err = svc.RevokeBreakGlass(bgCtx(), &pb.RevokeBreakGlassRequest{ProjectId: 1, ActivationId: act.GetId()})
	require.NoError(t, err)
}

func TestBreakGlass_ActivateRequiresJustification(t *testing.T) {
	svc := newBreakGlassService(t)
	_, err := svc.ActivateBreakGlass(bgCtx(), &pb.ActivateBreakGlassRequest{ProjectId: 1, Justification: ""})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestBreakGlass_Unauthenticated(t *testing.T) {
	svc := newBreakGlassService(t)
	_, err := svc.ActivateBreakGlass(context.Background(), &pb.ActivateBreakGlassRequest{ProjectId: 1, Justification: "x"})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// TestBreakGlass_ZeroProjectIDRejectedBeforeAuthz guards against the gap where
// ListBreakGlassActivations/RevokeBreakGlass called authorizeScoped(ctx, ...,
// core.Scope{ProjectID: uint(req.GetProjectId())}, ...) without first rejecting
// project_id == 0, unlike every machine-identity RPC. core.Scope{} (ProjectID 0)
// is the GLOBAL scope, so a project_id: 0 request was authorized against
// roles.read/roles.assign at GLOBAL scope instead of being rejected up front.
//
// This is proven by giving the actor a roles.read/roles.assign grant ONLY at
// project 1 (via the "admin" role, which bypasses per-permission checks but
// ONLY within the scope it is assigned — see adminRoleNames in
// internal/core/authz.go) and NO global grant at all. Before the fix, calling
// with ProjectId: 0 would route into authorizeScoped(Scope{ProjectID: 0}) — the
// actor holds no global grant, so that call fails PermissionDenied only AFTER
// evaluating the (wrong) global-scope authorization check. After the fix, the
// RPC rejects with InvalidArgument before authorizeScoped/the core layer are
// ever reached, matching the machine-identity RPCs' project_id != 0 guard.
func TestBreakGlass_ZeroProjectIDRejectedBeforeAuthz(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	require.NoError(t, h.DB.AutoMigrate(&models.BreakGlassActivation{}, &models.AuditEvent{}))

	const scopedUserID = uint(2)
	proj := uint(1)
	// role 2 = "admin": grants roles.read/roles.assign and admin bypass, but
	// ONLY within project 1's scope — this user holds NO global-scope grant.
	h.AssignUserRole(t, scopedUserID, 2, &proj)

	ctx := authCtx(scopedUserID, "project-scoped-admin", "roles.read", "roles.assign")
	svc := NewBreakGlassService(h.CoreService)

	_, err := svc.ListBreakGlassActivations(ctx, &pb.ListBreakGlassActivationsRequest{ProjectId: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err),
		"project_id: 0 must be rejected before the (wrong) global-scope authorization check runs")

	_, err = svc.RevokeBreakGlass(ctx, &pb.RevokeBreakGlassRequest{ProjectId: 0, ActivationId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err),
		"project_id: 0 must be rejected before the (wrong) global-scope authorization check runs")
}

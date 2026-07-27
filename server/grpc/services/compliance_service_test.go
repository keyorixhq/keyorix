package services

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func newComplianceService(t *testing.T) *ComplianceGRPCService {
	t.Helper()
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	// Admin-context user (id 1) = super_admin (global); denied tests use an
	// ungranted user id so core.Authorize refuses them.
	h.AssignUserRole(t, 1, 1, nil)
	return NewComplianceService(h.CoreService)
}

func compCtx() context.Context {
	return authCtx(1, "admin", permAuditRead)
}

func TestComplianceService_GetCompliancePosture(t *testing.T) {
	svc := newComplianceService(t)
	p, err := svc.GetCompliancePosture(compCtx(), &emptypb.Empty{})
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.NotNil(t, p.GetGeneratedAt())
	// The sub-rollups are always populated (zero-valued on an empty deployment).
	require.NotNil(t, p.GetAuditIntegrity())
	require.NotNil(t, p.GetAccessGovernance())
	require.NotNil(t, p.GetIdentity())
	require.NotNil(t, p.GetClassification())
	require.NotNil(t, p.GetClassification().GetDynamicConfigs())
	require.NotNil(t, p.GetRetention())
	require.NotNil(t, p.GetRisk())
}

func TestComplianceService_GetComplianceControls(t *testing.T) {
	svc := newComplianceService(t)
	c, err := svc.GetComplianceControls(compCtx(), &emptypb.Empty{})
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.NotNil(t, c.GetGeneratedAt())
	require.NotNil(t, c.GetSummary())
	// The control matrix is a fixed set of controls Keyorix evaluates — never empty.
	require.NotEmpty(t, c.GetControls())
	assert.Equal(t, int32(len(c.GetControls())), c.GetSummary().GetTotal())
	// Each control carries an id, a status, and framework refs.
	for _, ctl := range c.GetControls() {
		assert.NotEmpty(t, ctl.GetId(), "control id")
		assert.NotEmpty(t, ctl.GetStatus(), "control status")
		require.NotNil(t, ctl.GetFrameworks())
	}
}

func TestComplianceService_Unauthenticated(t *testing.T) {
	svc := newComplianceService(t)
	_, err := svc.GetCompliancePosture(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	_, err = svc.GetComplianceControls(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestComplianceService_PermissionDenied(t *testing.T) {
	svc := newComplianceService(t)
	ctx := authCtx(7, "nobody") // ungranted user → denied
	_, err := svc.GetCompliancePosture(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = svc.GetComplianceControls(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestComplianceService_SystemViewerDenied is a regression test for CP-001 /
// CP-008: a system_viewer (holding only "system.read") must NOT be able to
// read deployment-wide compliance posture or the control matrix via gRPC.
// Before the fix both RPCs were gated on "system.read", which is assigned to
// every created user and breaks segregation-of-duties with the HTTP layer that
// has always required "audit.read".
func TestComplianceService_SystemViewerDenied(t *testing.T) {
	svc := newComplianceService(t)
	// Simulate a system_viewer: authenticated but only holds system.read, not audit.read.
	ctx := authCtx(2, "system_viewer", "system.read")

	_, err := svc.GetCompliancePosture(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err),
		"system_viewer with only system.read must not access GetCompliancePosture")

	_, err = svc.GetComplianceControls(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err),
		"system_viewer with only system.read must not access GetComplianceControls")
}

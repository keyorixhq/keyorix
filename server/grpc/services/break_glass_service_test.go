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

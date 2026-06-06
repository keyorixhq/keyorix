package services

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func newSystemService(t *testing.T) *SystemGRPCService {
	t.Helper()
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	cfg := &config.Config{Environment: "test"}
	cfg.Storage.Type = "local"
	return NewSystemService(h.CoreService, cfg)
}

func sysCtx() context.Context {
	return authCtx(1, "admin", "system.read")
}

func TestSystemService_HealthCheck_Public(t *testing.T) {
	svc := newSystemService(t)
	// No auth context required — health is a public liveness probe.
	resp, err := svc.HealthCheck(context.Background(), &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, "healthy", resp.GetStatus())
	assert.NotEmpty(t, resp.GetVersion())
}

func TestSystemService_GetSystemInfo(t *testing.T) {
	svc := newSystemService(t)
	info, err := svc.GetSystemInfo(sysCtx(), &emptypb.Empty{})
	require.NoError(t, err)
	assert.NotEmpty(t, info.GetGoVersion())
	assert.NotEmpty(t, info.GetPlatform())
	assert.Equal(t, "test", info.GetEnvironment())
	require.NotNil(t, info.GetDatabase())
	assert.Equal(t, "local", info.GetDatabase().GetType())
}

func TestSystemService_GetSystemInfo_Unauthenticated(t *testing.T) {
	svc := newSystemService(t)
	_, err := svc.GetSystemInfo(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestSystemService_GetSystemInfo_PermissionDenied(t *testing.T) {
	svc := newSystemService(t)
	ctx := authCtx(1, "nobody") // no system.read
	_, err := svc.GetSystemInfo(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestSystemService_GetMetrics(t *testing.T) {
	svc := newSystemService(t)
	m, err := svc.GetMetrics(sysCtx(), &emptypb.Empty{})
	require.NoError(t, err)
	require.NotNil(t, m.GetSecrets())
	require.NotNil(t, m.GetUsers())
	require.NotNil(t, m.GetRequests())
	require.NotNil(t, m.GetPerformance())
	require.NotNil(t, m.GetSystem())
	// Goroutine count is always positive in a running test binary.
	assert.Greater(t, m.GetSystem().GetGoroutines(), uint32(0))
}

package grpc_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

// TestGRPCServer_EndToEnd drives the real NewServer wiring (all six services +
// the real auth interceptor) over an in-process bufconn connection. Unlike the
// per-service unit tests (which inject the user context directly), this exercises
// the full path: bearer token in metadata → interceptor validates the session →
// resolves RBAC permissions → service → core.
func TestGRPCServer_EndToEnd(t *testing.T) {
	const token = "e2e-session-token"

	// Real core with a fully seeded RBAC schema (super_admin has all perms).
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	require.NoError(t, h.DB.AutoMigrate(&models.Session{}, &models.SecretVersion{}))
	// An environment that belongs to the seeded project 1 (seeded envs have none).
	require.NoError(t, h.DB.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "dev"}).Error)

	// A user with the super_admin role (role id 1), and a live session token.
	user := h.CreateTestUser(t, "e2e-admin", 100)
	h.AssignUserRole(t, user.ID, 1, nil)
	expires := time.Now().Add(time.Hour)
	_, err := h.Storage.CreateSession(context.Background(), &models.Session{
		UserID: user.ID, SessionToken: token, ExpiresAt: &expires,
	})
	require.NoError(t, err)

	// Start the real server (TLS/reflection off by zero-value config) on bufconn.
	srv, err := keyorixgrpc.NewServer(&config.Config{}, h.CoreService)
	require.NoError(t, err)
	lis := bufconn.Listen(1024 * 1024)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	authedCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))

	t.Run("HealthCheck is public (no token)", func(t *testing.T) {
		resp, err := pb.NewSystemServiceClient(conn).HealthCheck(ctx, &emptypb.Empty{})
		require.NoError(t, err)
		assert.Equal(t, "healthy", resp.GetStatus())
	})

	secrets := pb.NewSecretServiceClient(conn)

	t.Run("CreateSecret without a token is rejected by the interceptor", func(t *testing.T) {
		_, err := secrets.CreateSecret(ctx, &pb.CreateSecretRequest{
			Name: "x", Value: "y", ProjectId: 1, EnvironmentId: 10, Type: "password",
		})
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	var createdID uint32
	t.Run("CreateSecret with a valid session token succeeds end-to-end", func(t *testing.T) {
		sec, err := secrets.CreateSecret(authedCtx, &pb.CreateSecretRequest{
			Name: "e2e-secret", Value: "s3cr3t", ProjectId: 1, EnvironmentId: 10, Type: "password",
		})
		require.NoError(t, err)
		assert.NotZero(t, sec.GetId())
		assert.Equal(t, "e2e-secret", sec.GetName())
		assert.Equal(t, uint32(1), sec.GetProjectId())
		createdID = sec.GetId()
	})

	t.Run("GetSecret with a valid session token returns it", func(t *testing.T) {
		sec, err := secrets.GetSecret(authedCtx, &pb.GetSecretRequest{Id: createdID})
		require.NoError(t, err)
		assert.Equal(t, "e2e-secret", sec.GetName())
	})
}

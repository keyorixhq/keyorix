package grpc

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	"github.com/keyorixhq/keyorix/server/grpc/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

var lis *bufconn.Listener

// bufDialer is a helper function for testing with bufconn
func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

// newTestServer creates a gRPC server with the share service registered for testing.
func newTestServer(t *testing.T) (*grpc.Server, *services.ShareGRPCService) {
	t.Helper()
	shareService, err := services.NewShareService(nil)
	require.NoError(t, err)

	server := grpc.NewServer(
		grpc.UnaryInterceptor(interceptors.AuthInterceptor()),
	)
	return server, shareService
}

// authCtx builds a context carrying a UserContext value using the exported key helper.
func authCtx(ctx context.Context, user *interceptors.UserContext) context.Context {
	return context.WithValue(ctx, interceptors.GetUserContextKey(), user)
}

// TestSharingGRPCServiceDirect tests the ShareGRPCService methods directly (no network).
// This avoids the need for generated proto client/server stubs.
func TestSharingGRPCServiceDirect(t *testing.T) {
	err := i18n.InitializeForTesting()
	require.NoError(t, err)
	defer i18n.ResetForTesting()

	shareService, err := services.NewShareService(nil)
	require.NoError(t, err)
	require.NotNil(t, shareService)

	ctx := context.Background()

	t.Run("Unauthenticated ShareSecret returns error", func(t *testing.T) {
		req := &services.ShareSecretRequest{
			SecretID:    1,
			RecipientID: 2,
			Permission:  "read",
		}
		_, err := shareService.ShareSecret(ctx, req)
		assert.Error(t, err)
	})

	t.Run("Authenticated user without write permission is denied", func(t *testing.T) {
		user := &interceptors.UserContext{
			UserID:      3,
			Username:    "limited",
			Permissions: []string{"secrets.read"},
		}
		authed := authCtx(ctx, user)

		req := &services.ShareSecretRequest{
			SecretID:    1,
			RecipientID: 2,
			Permission:  "read",
		}
		_, err := shareService.ShareSecret(authed, req)
		assert.Error(t, err)
	})

	t.Run("Invalid secret ID returns error", func(t *testing.T) {
		user := &interceptors.UserContext{
			UserID:      1,
			Username:    "testuser",
			Permissions: []string{"secrets.write", "secrets.read"},
		}
		authed := authCtx(ctx, user)

		req := &services.ShareSecretRequest{
			SecretID:    0, // invalid
			RecipientID: 2,
			Permission:  "read",
		}
		_, err := shareService.ShareSecret(authed, req)
		assert.Error(t, err)
	})

	t.Run("Invalid permission returns error", func(t *testing.T) {
		user := &interceptors.UserContext{
			UserID:      1,
			Username:    "testuser",
			Permissions: []string{"secrets.write"},
		}
		authed := authCtx(ctx, user)

		req := &services.ShareSecretRequest{
			SecretID:    1,
			RecipientID: 2,
			Permission:  "invalid",
		}
		_, err := shareService.ShareSecret(authed, req)
		assert.Error(t, err)
	})

	t.Run("ListSecretShares unauthenticated returns error", func(t *testing.T) {
		req := &services.ListSecretSharesRequest{SecretID: 1}
		_, err := shareService.ListSecretShares(ctx, req)
		assert.Error(t, err)
	})

	t.Run("UpdateSharePermission unauthenticated returns error", func(t *testing.T) {
		req := &services.UpdateSharePermissionRequest{ShareID: 1, Permission: "write"}
		_, err := shareService.UpdateSharePermission(ctx, req)
		assert.Error(t, err)
	})

	t.Run("RevokeShare unauthenticated returns error", func(t *testing.T) {
		req := &services.RevokeShareRequest{ShareID: 1}
		_, err := shareService.RevokeShare(ctx, req)
		assert.Error(t, err)
	})
}

// TestSharingGRPCConcurrency tests concurrent direct calls to the service.
func TestSharingGRPCConcurrency(t *testing.T) {
	err := i18n.InitializeForTesting()
	require.NoError(t, err)
	defer i18n.ResetForTesting()

	shareService, err := services.NewShareService(nil)
	require.NoError(t, err)

	ctx := context.Background()
	user := &interceptors.UserContext{
		UserID:      1,
		Username:    "testuser",
		Permissions: []string{"secrets.write"},
	}
	authed := authCtx(ctx, user)

	t.Run("Concurrent Share Operations", func(t *testing.T) {
		const numGoroutines = 10
		const requestsPerGoroutine = 5

		results := make(chan error, numGoroutines*requestsPerGoroutine)

		for i := 0; i < numGoroutines; i++ {
			go func(goroutineID int) {
				for j := 0; j < requestsPerGoroutine; j++ {
					req := &services.ShareSecretRequest{
						SecretID:    uint32(goroutineID + 1),
						RecipientID: uint32(goroutineID*requestsPerGoroutine + j + 10),
						Permission:  "read",
					}
					_, err := shareService.ShareSecret(authed, req)
					results <- err
				}
			}(i)
		}

		errorCount := 0
		for i := 0; i < numGoroutines*requestsPerGoroutine; i++ {
			select {
			case err := <-results:
				if err != nil {
					errorCount++
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Timeout waiting for concurrent requests")
			}
		}

		// All should fail (nil coreService), but none should panic
		assert.Equal(t, numGoroutines*requestsPerGoroutine, errorCount)
	})
}

// Ensure newTestServer and grpc/bufconn imports are used to avoid compile errors.
var _ = newTestServer
var _ = grpc.NewServer
var _ = insecure.NewCredentials
var _ = bufconn.Listen

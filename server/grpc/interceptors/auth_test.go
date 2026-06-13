package interceptors

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// secretMethod is a representative non-public RPC method that requires auth.
const secretMethod = "/keyorix.v1.SecretService/GetSecret"

// okHandler records the context it was invoked with and returns a sentinel.
func okHandler(captured *context.Context) grpc.UnaryHandler {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		if captured != nil {
			*captured = ctx
		}
		return "ok", nil
	}
}

func bearerCtx(token string) context.Context {
	md := metadata.Pairs("authorization", "Bearer "+token)
	return metadata.NewIncomingContext(context.Background(), md)
}

// setupAuthHelper builds an RBAC test helper and migrates the sessions table,
// which the base helper does not include but the auth path requires.
func setupAuthHelper(t *testing.T) *testhelper.RBACTestHelper {
	t.Helper()
	h := testhelper.NewRBACTestHelper(t)
	require.NoError(t, h.DB.AutoMigrate(&models.Session{}))
	return h
}

// mintSessionForTest inserts a user and a session token directly via storage and
// returns the token. expiresAt controls whether the session is live or expired.
func mintSessionForTest(t *testing.T, h *testhelper.RBACTestHelper, userID uint, username, token string, expiresAt time.Time) {
	t.Helper()
	h.CreateTestUser(t, username, userID)
	_, err := h.Storage.CreateSession(context.Background(), &models.Session{
		UserID:       userID,
		SessionToken: token,
		ExpiresAt:    &expiresAt,
	})
	require.NoError(t, err)
}

func TestAuthInterceptor_ValidSessionPopulatesUserContext(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	mintSessionForTest(t, h, 9001, "grpc-alice", "live-token", time.Now().Add(time.Hour))

	var captured context.Context
	interceptor := AuthInterceptor(h.CoreService)
	resp, err := interceptor(bearerCtx("live-token"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(&captured))

	require.NoError(t, err)
	assert.Equal(t, "ok", resp)

	user := GetUserFromGRPCContext(captured)
	require.NotNil(t, user, "handler context must carry the authenticated user")
	assert.Equal(t, uint(9001), user.UserID)
	assert.Equal(t, "grpc-alice", user.Username)
}

// Regression guard: the removed mock validator granted full admin to the literal
// token "valid-token". It must now be rejected like any other unknown token.
func TestAuthInterceptor_LegacyBackdoorTokenRejected(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()

	interceptor := AuthInterceptor(h.CoreService)
	for _, tok := range []string{"valid-token", "test-token"} {
		_, err := interceptor(bearerCtx(tok), nil,
			&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(nil))
		require.Error(t, err, "legacy mock token %q must not authenticate", tok)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	}
}

func TestAuthInterceptor_ExpiredSessionRejected(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	mintSessionForTest(t, h, 9002, "grpc-bob", "stale-token", time.Now().Add(-time.Minute))

	interceptor := AuthInterceptor(h.CoreService)
	_, err := interceptor(bearerCtx("stale-token"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(nil))
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAuthInterceptor_MissingAndMalformedCredentials(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	interceptor := AuthInterceptor(h.CoreService)
	info := &grpc.UnaryServerInfo{FullMethod: secretMethod}

	cases := map[string]context.Context{
		"no metadata":    context.Background(),
		"no auth header": metadata.NewIncomingContext(context.Background(), metadata.MD{}),
		"not bearer":     metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Basic abc")),
		"empty bearer":   bearerCtx(""),
		"unknown token":  bearerCtx("nope"),
	}
	for name, ctx := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := interceptor(ctx, nil, info, okHandler(nil))
			require.Error(t, err)
			assert.Equal(t, codes.Unauthenticated, status.Code(err))
		})
	}
}

// A nil core service must fail closed (never authenticate) rather than panic.
func TestAuthInterceptor_NilCoreFailsClosed(t *testing.T) {
	interceptor := AuthInterceptor(nil)
	_, err := interceptor(bearerCtx("whatever"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(nil))
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

// Public methods (health, reflection) bypass authentication entirely.
func TestAuthInterceptor_PublicMethodBypassesAuth(t *testing.T) {
	interceptor := AuthInterceptor(nil) // never consulted for public methods
	var captured context.Context
	resp, err := interceptor(context.Background(), nil,
		&grpc.UnaryServerInfo{FullMethod: "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"},
		okHandler(&captured))

	require.NoError(t, err)
	assert.Equal(t, "ok", resp)
	assert.Nil(t, GetUserFromGRPCContext(captured), "public method must not set a user context")
}

// A personal access token authenticates over gRPC (previously rejected outright)
// AND its ADR-042 least-privilege restriction rides the handler context, so
// core.Authorize enforces scoping over gRPC exactly as it does over HTTP.
func TestAuthInterceptor_PATAuthenticatesAndEnforcesScope(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.PersonalAccessToken{}))

	h.CreateTestUser(t, "grpc-ci", 9100)
	proj2 := uint(2)
	h.AssignUserRole(t, 9100, 3, &proj2) // editor (secrets.read + secrets.write) in project 2

	// A token confined to secrets.read in project 2 only.
	res, err := h.CoreService.CreateOwnPAT(context.Background(), 9100, "ci", nil, []string{"secrets.read"}, 2, 0)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(res.PlainToken, "kx_pat_"))

	var captured context.Context
	interceptor := AuthInterceptor(h.CoreService)
	resp, err := interceptor(bearerCtx(res.PlainToken), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(&captured))
	require.NoError(t, err, "a kx_pat_ token must now authenticate over gRPC")
	assert.Equal(t, "ok", resp)

	user := GetUserFromGRPCContext(captured)
	require.NotNil(t, user)
	assert.Equal(t, uint(9100), user.UserID, "authenticated as the PAT's owner")

	// Restriction is on the handler context → core.Authorize enforces it.
	readP2, err := h.CoreService.Authorize(captured, 9100, "secrets.read", core.Scope{ProjectID: 2})
	require.NoError(t, err)
	assert.True(t, readP2, "in-scope read allowed (restriction permits + owner's role grants)")

	writeP2, err := h.CoreService.Authorize(captured, 9100, "secrets.write", core.Scope{ProjectID: 2})
	require.NoError(t, err)
	assert.False(t, writeP2, "permission outside the token's allowlist is denied")

	readP3, err := h.CoreService.Authorize(captured, 9100, "secrets.read", core.Scope{ProjectID: 3})
	require.NoError(t, err)
	assert.False(t, readP3, "scope outside the token's project is denied")
}

// An invalid PAT fails closed with Unauthenticated, same as a bad session token.
func TestAuthInterceptor_InvalidPATRejected(t *testing.T) {
	h := setupAuthHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.PersonalAccessToken{}))

	interceptor := AuthInterceptor(h.CoreService)
	_, err := interceptor(bearerCtx("kx_pat_bogus"), nil,
		&grpc.UnaryServerInfo{FullMethod: secretMethod}, okHandler(nil))
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

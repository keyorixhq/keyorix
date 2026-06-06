package interceptors

import (
	"context"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// UserContext represents the authenticated user context for gRPC
type UserContext struct {
	UserID      uint     `json:"user_id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

// contextKey is used for context keys to avoid collisions
type contextKey string

const (
	userContextKey contextKey = "grpc_user"
)

// AuthInterceptor returns a unary server interceptor that authenticates each
// request against a real session token via the core service.
func AuthInterceptor(coreService *core.KeyorixCore) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Skip authentication for certain methods
		if isPublicMethod(info.FullMethod) {
			return handler(ctx, req)
		}

		// Extract and validate token
		userCtx, err := authenticateRequest(ctx, coreService)
		if err != nil {
			return nil, err
		}

		// Add user context to request context
		newCtx := context.WithValue(ctx, userContextKey, userCtx)
		return handler(newCtx, req)
	}
}

// StreamAuthInterceptor returns a stream server interceptor that authenticates
// each stream against a real session token via the core service.
func StreamAuthInterceptor(coreService *core.KeyorixCore) grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// Skip authentication for certain methods
		if isPublicMethod(info.FullMethod) {
			return handler(srv, stream)
		}

		// Extract and validate token
		userCtx, err := authenticateRequest(stream.Context(), coreService)
		if err != nil {
			return err
		}

		// Create a new stream with user context
		wrappedStream := &wrappedServerStream{
			ServerStream: stream,
			ctx:          context.WithValue(stream.Context(), userContextKey, userCtx),
		}

		return handler(srv, wrappedStream)
	}
}

// wrappedServerStream wraps grpc.ServerStream to override context
type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}

// authenticateRequest extracts the bearer session token from the request
// metadata and validates it against the core service — the same session-token
// path the HTTP API uses. On success it returns the authenticated user's
// context (id, identity, roles, permissions) for downstream authorization.
func authenticateRequest(ctx context.Context, coreService *core.KeyorixCore) (*UserContext, error) {
	if coreService == nil {
		// Fail closed: a server wired without a core service must not authenticate.
		return nil, status.Errorf(codes.Internal, "authentication unavailable")
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "Missing metadata")
	}

	// Extract authorization header
	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "Missing authorization header")
	}

	authHeader := authHeaders[0]
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, status.Errorf(codes.Unauthenticated, "Invalid authorization header format")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return nil, status.Errorf(codes.Unauthenticated, "Missing token")
	}

	// Validate the session token (existence + expiry) and resolve the user.
	user, _, err := coreService.ValidateSessionToken(ctx, token)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Invalid or expired token")
	}

	// Resolve roles + permissions for downstream per-method authorization.
	identity, err := coreService.GetUserIdentity(ctx, user.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to resolve user identity")
	}

	return &UserContext{
		UserID:      user.ID,
		Username:    user.Username,
		Email:       user.Email,
		Roles:       identity.Roles,
		Permissions: identity.Permissions,
	}, nil
}

// isPublicMethod checks if a gRPC method is public (doesn't require authentication)
func isPublicMethod(method string) bool {
	publicMethods := []string{
		"/grpc.health.v1.Health/Check",
		"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
		"/keyorix.v1.SystemService/HealthCheck", // liveness probe — no auth
	}

	for _, publicMethod := range publicMethods {
		if method == publicMethod {
			return true
		}
	}

	return false
}

// GetUserFromGRPCContext extracts the user context from the gRPC request context
func GetUserFromGRPCContext(ctx context.Context) *UserContext {
	if userCtx, ok := ctx.Value(userContextKey).(*UserContext); ok {
		return userCtx
	}
	return nil
}

// GetUserContextKey returns the context key for user context (for testing)
func GetUserContextKey() contextKey {
	return userContextKey
}

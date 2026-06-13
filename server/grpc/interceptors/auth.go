package interceptors

import (
	"context"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// patTokenPrefix marks a personal access token (ADR-027/042); anything else is
// treated as a session token. Matches the HTTP middleware's routing.
const patTokenPrefix = "kx_pat_"

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
		userCtx, restriction, err := authenticateRequest(ctx, coreService)
		if err != nil {
			return nil, err
		}

		// Add user context to request context
		newCtx := context.WithValue(ctx, userContextKey, userCtx)
		// Carry a PAT's least-privilege restriction (ADR-042) so core.Authorize
		// enforces it on every authorization check this RPC makes.
		if restriction != nil {
			newCtx = core.WithPATRestriction(newCtx, restriction)
		}
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
		userCtx, restriction, err := authenticateRequest(stream.Context(), coreService)
		if err != nil {
			return err
		}

		// Create a new stream with user context (+ PAT restriction when present).
		streamCtx := context.WithValue(stream.Context(), userContextKey, userCtx)
		if restriction != nil {
			streamCtx = core.WithPATRestriction(streamCtx, restriction)
		}
		wrappedStream := &wrappedServerStream{
			ServerStream: stream,
			ctx:          streamCtx,
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

// authenticateRequest extracts the bearer token from the request metadata and
// validates it against the core service — the same paths the HTTP API uses. A
// kx_pat_ token authenticates as its owning user via ValidatePATToken and may
// carry a least-privilege restriction (ADR-042); anything else is a session
// token. On success it returns the authenticated user's context (id, identity,
// roles, permissions) and the PAT restriction (nil for sessions) for downstream
// authorization.
func authenticateRequest(ctx context.Context, coreService *core.KeyorixCore) (*UserContext, *core.PATRestriction, error) {
	if coreService == nil {
		// Fail closed: a server wired without a core service must not authenticate.
		return nil, nil, status.Errorf(codes.Internal, "authentication unavailable")
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, nil, status.Errorf(codes.Unauthenticated, "Missing metadata")
	}

	// Extract authorization header
	authHeaders := md.Get("authorization")
	if len(authHeaders) == 0 {
		return nil, nil, status.Errorf(codes.Unauthenticated, "Missing authorization header")
	}

	authHeader := authHeaders[0]
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, nil, status.Errorf(codes.Unauthenticated, "Invalid authorization header format")
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return nil, nil, status.Errorf(codes.Unauthenticated, "Missing token")
	}

	// Validate the token (existence + expiry/revocation) and resolve the user. A
	// PAT resolves to its owner plus an optional restriction; both fail closed.
	var (
		user        *models.User
		restriction *core.PATRestriction
		err         error
	)
	if strings.HasPrefix(token, patTokenPrefix) {
		user, _, restriction, err = coreService.ValidatePATToken(ctx, token)
	} else {
		user, _, err = coreService.ValidateSessionToken(ctx, token)
	}
	if err != nil {
		return nil, nil, status.Errorf(codes.Unauthenticated, "Invalid or expired token")
	}

	// Resolve roles + permissions for downstream per-method authorization.
	identity, err := coreService.GetUserIdentity(ctx, user.ID)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "failed to resolve user identity")
	}

	return &UserContext{
		UserID:      user.ID,
		Username:    user.Username,
		Email:       user.Email,
		Roles:       identity.Roles,
		Permissions: identity.Permissions,
	}, restriction, nil
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

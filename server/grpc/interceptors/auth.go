package interceptors

import (
	"context"
	"net"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Token-kind prefixes — match the HTTP middleware's routing. kx_pat_ is a personal
// access token (ADR-027/042); kx_machine_ a machine-identity token (ADR-030);
// anything else is a session token.
const (
	patTokenPrefix     = "kx_pat_"
	machineTokenPrefix = "kx_machine_"
)

// UserContext represents the authenticated principal for gRPC — a human user, or
// a machine identity (ADR-030) when MachineIdentityID is set and UserID is 0.
type UserContext struct {
	UserID      uint     `json:"user_id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	// ActorType is "machine_identity" for a machine principal, otherwise empty
	// (treated as a user). MachineIdentityID is the machine's id for that case.
	ActorType         string `json:"actor_type,omitempty"`
	MachineIdentityID uint   `json:"machine_identity_id,omitempty"`
}

// ActorKind returns the principal's actor type ("user" or "machine_identity"),
// defaulting to user for empty contexts.
func (u *UserContext) ActorKind() string {
	if u.ActorType == core.ActorTypeMachine {
		return core.ActorTypeMachine
	}
	return core.ActorTypeUser
}

// PrincipalID returns the id to authorize against: the machine identity id for a
// machine request, otherwise the user id.
func (u *UserContext) PrincipalID() uint {
	if u.ActorType == core.ActorTypeMachine {
		return u.MachineIdentityID
	}
	return u.UserID
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

	// A machine-identity token (ADR-030) authenticates as a machine principal — no
	// owning user, no admin bypass downstream (AuthorizePrincipal resolves machine
	// roles). Routed by prefix, fails closed.
	if strings.HasPrefix(token, machineTokenPrefix) {
		machine, roles, err := coreService.ValidateMachineToken(ctx, token)
		if err != nil {
			return nil, nil, status.Errorf(codes.Unauthenticated, "Invalid or expired token")
		}
		return &UserContext{
			Username:          machine.Name,
			Roles:             roles,
			ActorType:         core.ActorTypeMachine,
			MachineIdentityID: machine.ID,
		}, nil, nil
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

	// Enforce a PAT's network allowlist on the gRPC transport too (ADR-066), so the IP
	// restriction is not bypassable by switching from HTTP to gRPC. Fail-closed: an
	// undeterminable peer IP outside the allowlist is denied.
	if restriction != nil && len(restriction.AllowedCIDRs) > 0 {
		if !core.IPInCIDRs(grpcPeerIP(ctx), restriction.AllowedCIDRs) {
			return nil, nil, status.Errorf(codes.PermissionDenied, "token not permitted from this network")
		}
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

// grpcPeerIP returns the source IP of the gRPC call from its peer (TCP) address, or "" if
// it cannot be determined (which the fail-closed allowlist check then denies).
func grpcPeerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
		return host
	}
	return p.Addr.String()
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

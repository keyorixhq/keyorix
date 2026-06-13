package services

import (
	"context"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SecretGRPCService implements pb.SecretServiceServer, backing each RPC with the
// shared core service. Authentication/identity is established by the auth
// interceptor (see interceptors.AuthInterceptor) and read from the context.
type SecretGRPCService struct {
	pb.UnimplementedSecretServiceServer
	core *core.KeyorixCore
}

// Compile-time assertion that the service satisfies the generated interface.
var _ pb.SecretServiceServer = (*SecretGRPCService)(nil)

// NewSecretService creates a secret gRPC service backed by the shared core.
func NewSecretService(coreService *core.KeyorixCore) *SecretGRPCService {
	return &SecretGRPCService{core: coreService}
}

// CreateSecret creates a new secret.
func (s *SecretGRPCService) CreateSecret(ctx context.Context, req *pb.CreateSecretRequest) (*pb.Secret, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetName() == "" || req.GetValue() == "" || req.GetProjectId() == 0 || req.GetEnvironmentId() == 0 || req.GetType() == "" {
		return nil, status.Error(codes.InvalidArgument, "name, value, project_id, environment_id and type are required")
	}
	// Authorize secrets.write AT THE TARGET project/environment, not the flat
	// global permission set — a project-scoped writer must not create in another
	// project. Mirrors the HTTP CreateSecret handler (scope from the body).
	scope := core.Scope{ProjectID: uint(req.GetProjectId()), EnvironmentID: uint(req.GetEnvironmentId())}
	if allowed, err := s.core.AuthorizePrincipal(ctx, user.ActorKind(), user.PrincipalID(), "secrets.write", scope); err != nil || !allowed {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to create secrets in this project")
	}

	secret, err := s.core.CreateSecret(ctx, &core.CreateSecretRequest{
		Name:          req.GetName(),
		Value:         []byte(req.GetValue()),
		ProjectID:     uint(req.GetProjectId()),
		EnvironmentID: uint(req.GetEnvironmentId()),
		Type:          req.GetType(),
		MaxReads:      int32PtrToIntPtr(req.MaxReads),
		Expiration:    tsToTimePtr(req.GetExpiration()),
		Metadata:      req.GetMetadata(),
		Tags:          req.GetTags(),
		CreatedBy:     user.Username,
		OwnerID:       user.UserID,
	})
	if err != nil {
		return nil, mapSecretError(err)
	}
	return secretNodeToProto(secret), nil
}

// GetSecret returns a secret's metadata (subject to ownership/share checks).
func (s *SecretGRPCService) GetSecret(ctx context.Context, req *pb.GetSecretRequest) (*pb.Secret, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), "secrets.read"); err != nil {
		return nil, err
	}
	secret, err := s.core.GetSecretWithPermissionCheck(ctx, uint(req.GetId()), user.UserID)
	if err != nil {
		return nil, mapSecretError(err)
	}
	return secretNodeToProto(secret), nil
}

// GetSecretValue returns a secret's decrypted value (counts toward max_reads).
// version_number/read_count are not populated here — use GetSecretVersions for
// version history.
func (s *SecretGRPCService) GetSecretValue(ctx context.Context, req *pb.GetSecretRequest) (*pb.SecretValue, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), "secrets.read"); err != nil {
		return nil, err
	}
	// Resolve the name first (metadata read, no read-count side effect).
	secret, err := s.core.GetSecretWithPermissionCheck(ctx, uint(req.GetId()), user.UserID)
	if err != nil {
		return nil, mapSecretError(err)
	}
	value, err := s.core.GetSecretValueWithPermissionCheck(ctx, uint(req.GetId()), user.UserID)
	if err != nil {
		return nil, mapSecretError(err)
	}
	return &pb.SecretValue{
		Id:    req.GetId(),
		Name:  secret.Name,
		Value: string(value),
	}, nil
}

// UpdateSecret updates a secret; a non-empty value rotates it to a new version.
func (s *SecretGRPCService) UpdateSecret(ctx context.Context, req *pb.UpdateSecretRequest) (*pb.Secret, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), "secrets.write"); err != nil {
		return nil, err
	}

	updateReq := &core.UpdateSecretRequest{
		ID:         uint(req.GetId()),
		MaxReads:   int32PtrToIntPtr(req.MaxReads),
		Expiration: tsToTimePtr(req.GetExpiration()),
		Metadata:   req.GetMetadata(),
		Tags:       req.GetTags(),
		UpdatedBy:  user.Username,
		UserID:     user.UserID,
	}
	if v := req.GetValue(); v != "" {
		updateReq.Value = []byte(v)
	}

	secret, err := s.core.UpdateSecretWithPermissionCheck(ctx, updateReq)
	if err != nil {
		return nil, mapSecretError(err)
	}
	return secretNodeToProto(secret), nil
}

// DeleteSecret deletes a secret (owner-only, enforced by core).
func (s *SecretGRPCService) DeleteSecret(ctx context.Context, req *pb.DeleteSecretRequest) (*emptypb.Empty, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), "secrets.delete"); err != nil {
		return nil, err
	}
	if err := s.core.DeleteSecretWithPermissionCheck(ctx, uint(req.GetId()), user.UserID); err != nil {
		return nil, mapSecretError(err)
	}
	return &emptypb.Empty{}, nil
}

// ListSecrets lists secrets visible to the caller with sharing context.
func (s *SecretGRPCService) ListSecrets(ctx context.Context, req *pb.ListSecretsRequest) (*pb.ListSecretsResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	// Authorize at the requested project/environment scope (mirrors the HTTP list
	// route's ScopeFromQuery); 0/0 means global. ListSecretsWithSharingInfo then
	// filters the results to what the caller may actually see.
	listScope := core.Scope{ProjectID: uint(req.GetProjectId()), EnvironmentID: uint(req.GetEnvironmentId())}
	if allowed, err := s.core.AuthorizePrincipal(ctx, user.ActorKind(), user.PrincipalID(), "secrets.read", listScope); err != nil || !allowed {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to list secrets")
	}

	page := int(req.GetPage())
	if page < 1 {
		page = 1
	}
	pageSize := int(req.GetPageSize())
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	filter := &models.SecretListFilter{
		Search:         optString(req.Search),
		ProjectID:      optUint(req.ProjectId),
		EnvironmentID:  optUint(req.EnvironmentId),
		Type:           optString(req.Type),
		Permission:     req.GetPermission(),
		ShowOwnedOnly:  req.GetShowOwnedOnly(),
		ShowSharedOnly: req.GetShowSharedOnly(),
		Page:           page,
		PageSize:       pageSize,
	}

	resp, err := s.core.ListSecretsWithSharingInfo(ctx, user.UserID, filter)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list secrets")
	}

	secrets := make([]*pb.Secret, 0, len(resp.Secrets))
	for _, sec := range resp.Secrets {
		secrets = append(secrets, sharingInfoToProto(sec))
	}
	return &pb.ListSecretsResponse{
		Secrets:     secrets,
		Total:       i64ToU32(resp.Total),
		Page:        intToU32(resp.Page),
		PageSize:    intToU32(resp.PageSize),
		TotalPages:  intToU32(resp.TotalPages),
		OwnedCount:  intToU32(resp.OwnedCount),
		SharedCount: intToU32(resp.SharedCount),
	}, nil
}

// GetSecretVersions returns a secret's version history (subject to access checks).
func (s *SecretGRPCService) GetSecretVersions(ctx context.Context, req *pb.GetSecretVersionsRequest) (*pb.GetSecretVersionsResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeSecretScoped(ctx, s.core, user, uint(req.GetId()), "secrets.read"); err != nil {
		return nil, err
	}
	versions, err := s.core.GetSecretVersionsWithPermissionCheck(ctx, uint(req.GetId()), user.UserID)
	if err != nil {
		return nil, mapSecretError(err)
	}
	out := make([]*pb.SecretVersion, 0, len(versions))
	for _, v := range versions {
		out = append(out, &pb.SecretVersion{
			VersionNumber: intToU32(v.VersionNumber),
			CreatedAt:     timestamppb.New(v.CreatedAt),
			ReadCount:     intToU32(v.ReadCount),
		})
	}
	return &pb.GetSecretVersionsResponse{Versions: out}, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// requireUser returns the authenticated user from the context or an
// Unauthenticated error. The auth interceptor populates this on every
// non-public RPC.
// authorizeSecretScoped resolves a secret's project/environment and checks the
// permission AT that scope — mirroring the HTTP RequireScopedPermission gate, so
// gRPC enforces the same scoped-RBAC model as HTTP rather than the flat, global
// permission set. A missing secret yields NotFound (not PermissionDenied) to
// avoid leaking existence; the downstream *WithPermissionCheck core calls still
// enforce ownership/share on top of this.
func authorizeSecretScoped(ctx context.Context, cs *core.KeyorixCore, actor *interceptors.UserContext, secretID uint, perm string) error {
	secret, err := cs.Storage().GetSecret(ctx, secretID)
	if err != nil {
		return status.Error(codes.NotFound, "secret not found")
	}
	scope := core.Scope{ProjectID: secret.ProjectID, EnvironmentID: secret.EnvironmentID}
	if allowed, err := cs.AuthorizePrincipal(ctx, actor.ActorKind(), actor.PrincipalID(), perm, scope); err != nil || !allowed {
		return status.Error(codes.PermissionDenied, "insufficient permissions for this secret")
	}
	return nil
}

// mapSecretError translates core errors into gRPC status codes.
func mapSecretError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found"):
		return status.Error(codes.NotFound, "secret not found")
	case strings.Contains(msg, "permission denied"), strings.Contains(msg, "access denied"):
		return status.Error(codes.PermissionDenied, "access denied to this secret")
	case strings.Contains(msg, "already exists"):
		return status.Error(codes.AlreadyExists, "secret with this name already exists")
	default:
		return status.Error(codes.Internal, "secret operation failed")
	}
}

// Shared proto-conversion, pagination, and identity helpers live in conversions.go.

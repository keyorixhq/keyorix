package services

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/utils/safeconv"
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
	if allowed, err := s.core.Authorize(ctx, user.UserID, "secrets.write", scope); err != nil || !allowed {
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
	if !hasPermission(user.Permissions, "secrets.read") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to read secrets")
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
	if !hasPermission(user.Permissions, "secrets.read") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to read secrets")
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
	if !hasPermission(user.Permissions, "secrets.write") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to update secrets")
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
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
	if !hasPermission(user.Permissions, "secrets.delete") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to delete secrets")
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
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
	if !hasPermission(user.Permissions, "secrets.read") {
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
	if !hasPermission(user.Permissions, "secrets.read") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to read secrets")
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
func requireUser(ctx context.Context) (*interceptors.UserContext, error) {
	user := interceptors.GetUserFromGRPCContext(ctx)
	if user == nil {
		return nil, status.Error(codes.Unauthenticated, "user not authenticated")
	}
	return user, nil
}

func hasPermission(permissions []string, required string) bool {
	for _, p := range permissions {
		if p == required {
			return true
		}
	}
	return false
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

func secretNodeToProto(n *models.SecretNode) *pb.Secret {
	return &pb.Secret{
		Id:            intToU32(int(n.ID)),
		Name:          n.Name,
		ProjectId:     intToU32(int(n.ProjectID)),
		EnvironmentId: intToU32(int(n.EnvironmentID)),
		Type:          n.Type,
		MaxReads:      intPtrToInt32Ptr(n.MaxReads),
		Expiration:    timePtrToTs(n.Expiration),
		Metadata:      metadataToMap(n.Metadata),
		Tags:          []string{}, // tags are not stored on the secret node
		Status:        n.Status,
		CreatedBy:     n.CreatedBy,
		OwnerId:       intToU32(int(n.OwnerID)),
		CreatedAt:     timestamppb.New(n.CreatedAt),
		UpdatedAt:     timestamppb.New(n.UpdatedAt),
		IsShared:      n.IsShared,
	}
}

func sharingInfoToProto(s *models.SecretWithSharingInfo) *pb.Secret {
	out := secretNodeToProto(s.SecretNode)
	out.ProjectName = s.ProjectName
	out.EnvironmentName = s.EnvironmentName
	out.IsShared = s.IsShared
	out.IsOwnedByUser = s.IsOwnedByUser
	out.UserPermission = s.UserPermission
	out.ShareCount = intToU32(s.ShareCount)
	return out
}

func metadataToMap(raw models.JSON) map[string]string {
	if len(raw) == 0 {
		return map[string]string{}
	}
	m := map[string]string{}
	_ = json.Unmarshal(raw, &m) // best-effort; non-string maps yield empty
	return m
}

// numeric conversions — overflow is unrealistic for IDs/counts; clamp on the
// off chance rather than failing the RPC.
func intToU32(v int) uint32 {
	x, err := safeconv.UintToUint32(uint(v))
	if err != nil || v < 0 {
		return 0
	}
	return x
}

func i64ToU32(v int64) uint32 {
	if v < 0 {
		return 0
	}
	return intToU32(int(v))
}

func intPtrToInt32Ptr(p *int) *int32 {
	if p == nil {
		return nil
	}
	v, err := safeconv.IntToInt32(*p)
	if err != nil {
		v = 0
	}
	return &v
}

func int32PtrToIntPtr(p *int32) *int {
	if p == nil {
		return nil
	}
	v := int(*p)
	return &v
}

func tsToTimePtr(ts *timestamppb.Timestamp) *time.Time {
	if ts == nil {
		return nil
	}
	t := ts.AsTime()
	return &t
}

func timePtrToTs(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func optString(p *string) *string {
	if p == nil || *p == "" {
		return nil
	}
	return p
}

func optUint(p *uint32) *uint {
	if p == nil || *p == 0 {
		return nil
	}
	v := uint(*p)
	return &v
}

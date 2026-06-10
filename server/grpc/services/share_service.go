package services

import (
	"context"
	"strings"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ShareGRPCService implements pb.ShareServiceServer, backing each RPC with the
// shared core service. Identity is established by the auth interceptor and read
// from the context.
type ShareGRPCService struct {
	pb.UnimplementedShareServiceServer
	core *core.KeyorixCore
}

// Compile-time assertion that the service satisfies the generated interface.
var _ pb.ShareServiceServer = (*ShareGRPCService)(nil)

// NewShareService creates a share gRPC service backed by the shared core.
func NewShareService(coreService *core.KeyorixCore) *ShareGRPCService {
	return &ShareGRPCService{core: coreService}
}

// ShareSecret shares a secret with another user or group.
func (s *ShareGRPCService) ShareSecret(ctx context.Context, req *pb.ShareSecretRequest) (*pb.ShareRecord, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if !hasPermission(user.Permissions, "secrets.write") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to share secrets")
	}
	if req.GetSecretId() == 0 || req.GetRecipientId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "secret_id and recipient_id are required")
	}
	if req.GetPermission() != "read" && req.GetPermission() != "write" {
		return nil, status.Error(codes.InvalidArgument, "permission must be 'read' or 'write'")
	}

	var record *models.ShareRecord
	if req.GetIsGroup() {
		record, err = s.core.ShareSecretWithGroup(ctx, &core.GroupShareSecretRequest{
			SecretID:   uint(req.GetSecretId()),
			GroupID:    uint(req.GetRecipientId()),
			Permission: req.GetPermission(),
			SharedBy:   user.UserID,
		})
	} else {
		record, err = s.core.ShareSecret(ctx, &core.ShareSecretRequest{
			SecretID:    uint(req.GetSecretId()),
			RecipientID: uint(req.GetRecipientId()),
			IsGroup:     false,
			Permission:  req.GetPermission(),
			SharedBy:    user.UserID,
		})
	}
	if err != nil {
		return nil, mapShareError(err)
	}
	return shareRecordToProto(record), nil
}

// ListSecretShares lists all shares for a secret.
func (s *ShareGRPCService) ListSecretShares(ctx context.Context, req *pb.ListSecretSharesRequest) (*pb.ListSharesResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if !hasPermission(user.Permissions, "secrets.read") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to view shares")
	}
	if req.GetSecretId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "secret_id is required")
	}

	shares, err := s.core.ListSecretSharesWithPermissionCheck(ctx, uint(req.GetSecretId()), user.UserID)
	if err != nil {
		return nil, mapShareError(err)
	}
	return sharesToResponse(shares, 1, len(shares)), nil
}

// ListUserShares lists shares created by the calling user.
func (s *ShareGRPCService) ListUserShares(ctx context.Context, req *pb.ListUserSharesRequest) (*pb.ListSharesResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if !hasPermission(user.Permissions, "secrets.read") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to view shares")
	}

	shares, err := s.core.ListSharesByUser(ctx, user.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list user shares")
	}
	page, pageSize := normalizePage(req.GetPage(), req.GetPageSize())
	return sharesToResponse(shares, page, pageSize), nil
}

// ListSharedSecrets lists secrets shared with the calling user.
func (s *ShareGRPCService) ListSharedSecrets(ctx context.Context, req *pb.ListSharedSecretsRequest) (*pb.ListSecretsResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if !hasPermission(user.Permissions, "secrets.read") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to view shared secrets")
	}

	secrets, err := s.core.ListSharedSecrets(ctx, user.UserID)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list shared secrets")
	}
	page, pageSize := normalizePage(req.GetPage(), req.GetPageSize())
	out := make([]*pb.Secret, 0, len(secrets))
	for _, sec := range secrets {
		out = append(out, secretNodeToProto(sec))
	}
	return &pb.ListSecretsResponse{
		Secrets:     out,
		Total:       intToU32(len(out)),
		Page:        intToU32(page),
		PageSize:    intToU32(pageSize),
		TotalPages:  intToU32(totalPages(len(out), pageSize)),
		SharedCount: intToU32(len(out)),
	}, nil
}

// UpdateSharePermission changes the permission level of an existing share.
func (s *ShareGRPCService) UpdateSharePermission(ctx context.Context, req *pb.UpdateSharePermissionRequest) (*pb.ShareRecord, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if !hasPermission(user.Permissions, "secrets.write") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to update shares")
	}
	if req.GetShareId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "share_id is required")
	}
	if req.GetPermission() != "read" && req.GetPermission() != "write" {
		return nil, status.Error(codes.InvalidArgument, "permission must be 'read' or 'write'")
	}

	record, err := s.core.UpdateSharePermission(ctx, &core.UpdateShareRequest{
		ShareID:    uint(req.GetShareId()),
		Permission: req.GetPermission(),
		UpdatedBy:  user.UserID,
	})
	if err != nil {
		return nil, mapShareError(err)
	}
	return shareRecordToProto(record), nil
}

// RevokeShare revokes a share.
func (s *ShareGRPCService) RevokeShare(ctx context.Context, req *pb.RevokeShareRequest) (*emptypb.Empty, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if !hasPermission(user.Permissions, "secrets.write") {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions to revoke shares")
	}
	if req.GetShareId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "share_id is required")
	}
	if err := s.core.RevokeShare(ctx, uint(req.GetShareId()), user.UserID); err != nil {
		return nil, mapShareError(err)
	}
	return &emptypb.Empty{}, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// mapShareError translates core sharing errors into gRPC status codes.
func mapShareError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found"):
		return status.Error(codes.NotFound, "share or secret not found")
	case strings.Contains(msg, "not authorized"), strings.Contains(msg, "permission denied"):
		return status.Error(codes.PermissionDenied, "not authorized for this share")
	default:
		return status.Error(codes.Internal, "share operation failed")
	}
}

func shareRecordToProto(r *models.ShareRecord) *pb.ShareRecord {
	return &pb.ShareRecord{
		Id:          intToU32(int(r.ID)),
		SecretId:    intToU32(int(r.SecretID)),
		OwnerId:     intToU32(int(r.OwnerID)),
		RecipientId: intToU32(int(r.RecipientID)),
		IsGroup:     r.IsGroup,
		Permission:  r.Permission,
		CreatedAt:   timestamppb.New(r.CreatedAt),
		UpdatedAt:   timestamppb.New(r.UpdatedAt),
	}
}

func sharesToResponse(shares []*models.ShareRecord, page, pageSize int) *pb.ListSharesResponse {
	out := make([]*pb.ShareRecord, 0, len(shares))
	for _, sh := range shares {
		out = append(out, shareRecordToProto(sh))
	}
	return &pb.ListSharesResponse{
		Shares:     out,
		Total:      intToU32(len(out)),
		Page:       intToU32(page),
		PageSize:   intToU32(pageSize),
		TotalPages: intToU32(totalPages(len(out), pageSize)),
	}
}

// Shared pagination helpers (normalizePage / totalPages) live in conversions.go.

package services

import (
	"context"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/keyorixhq/keyorix/internal/core"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)


// MachineIdentityGRPCService implements pb.MachineIdentityServiceServer (ADR-023/030).
// Authz mirrors the HTTP routes: list → users.read, every mutation → roles.assign,
// scoped to the target project.
type MachineIdentityGRPCService struct {
	pb.UnimplementedMachineIdentityServiceServer
	core *core.KeyorixCore
}

var _ pb.MachineIdentityServiceServer = (*MachineIdentityGRPCService)(nil)

// NewMachineIdentityService creates the service backed by the shared core.
func NewMachineIdentityService(coreService *core.KeyorixCore) *MachineIdentityGRPCService {
	return &MachineIdentityGRPCService{core: coreService}
}

func mapMachineError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found"):
		return status.Error(codes.NotFound, "machine identity or token not found")
	case strings.Contains(msg, "cannot transition"):
		return status.Error(codes.FailedPrecondition, msg)
	case strings.Contains(msg, "must be active"):
		return status.Error(codes.FailedPrecondition, msg)
	case strings.Contains(msg, "invalid") || strings.Contains(msg, "classification must be") || strings.Contains(msg, "required"):
		return status.Error(codes.InvalidArgument, msg)
	case strings.Contains(msg, "permission") || strings.Contains(msg, "denied"):
		return status.Error(codes.PermissionDenied, "access denied")
	default:
		return status.Error(codes.Internal, "machine identity operation failed")
	}
}

func machineActionToState(action string) (string, bool) {
	switch action {
	case "activate":
		return core.MachineActive, true
	case "suspend":
		return core.MachineSuspended, true
	case "revoke":
		return core.MachineRevoked, true
	default:
		return "", false
	}
}

func (s *MachineIdentityGRPCService) ListMachineIdentities(ctx context.Context, req *pb.ListMachineIdentitiesRequest) (*pb.ListMachineIdentitiesResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetProjectId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "project_id is required")
	}
	if err := authorizeScoped(ctx, s.core, user, "users.read", core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {
		return nil, err
	}
	rows, err := s.core.ListMachineIdentities(ctx, uint(req.GetProjectId()))
	if err != nil {
		return nil, mapMachineError(err)
	}
	out := make([]*pb.MachineIdentity, 0, len(rows))
	for _, m := range rows {
		out = append(out, machineIdentityToProto(m))
	}
	return &pb.ListMachineIdentitiesResponse{MachineIdentities: out}, nil
}

func (s *MachineIdentityGRPCService) CreateMachineIdentity(ctx context.Context, req *pb.CreateMachineIdentityRequest) (*pb.MachineIdentity, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetProjectId() == 0 || req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "project_id and name are required")
	}
	if err := authorizeScoped(ctx, s.core, user, permRolesAssign, core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {
		return nil, err
	}
	m, err := s.core.CreateMachineIdentity(ctx, uint(req.GetProjectId()), req.GetName(), req.GetIdentityType(), req.GetDescription(), req.GetClassification(), user.UserID)
	if err != nil {
		return nil, mapMachineError(err)
	}
	return machineIdentityToProto(m), nil
}

func (s *MachineIdentityGRPCService) TransitionMachineIdentity(ctx context.Context, req *pb.TransitionMachineIdentityRequest) (*pb.MachineIdentity, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetProjectId() == 0 || req.GetMachineId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errProjectAndMachineRequired)
	}
	to, ok := machineActionToState(req.GetAction())
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "action must be activate, suspend, or revoke")
	}
	if err := authorizeScoped(ctx, s.core, user, permRolesAssign, core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {
		return nil, err
	}
	m, err := s.core.TransitionMachineIdentity(ctx, uint(req.GetProjectId()), uint(req.GetMachineId()), to, user.UserID)
	if err != nil {
		return nil, mapMachineError(err)
	}
	return machineIdentityToProto(m), nil
}

func (s *MachineIdentityGRPCService) ClassifyMachineIdentity(ctx context.Context, req *pb.ClassifyMachineIdentityRequest) (*pb.MachineIdentity, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetProjectId() == 0 || req.GetMachineId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errProjectAndMachineRequired)
	}
	if err := authorizeScoped(ctx, s.core, user, permRolesAssign, core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {
		return nil, err
	}
	m, err := s.core.ClassifyMachineIdentity(ctx, uint(req.GetProjectId()), uint(req.GetMachineId()), req.GetClassification(), user.UserID)
	if err != nil {
		return nil, mapMachineError(err)
	}
	return machineIdentityToProto(m), nil
}

func (s *MachineIdentityGRPCService) IssueMachineToken(ctx context.Context, req *pb.IssueMachineTokenRequest) (*pb.IssueMachineTokenResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetProjectId() == 0 || req.GetMachineId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errProjectAndMachineRequired)
	}
	if err := authorizeScoped(ctx, s.core, user, permRolesAssign, core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {
		return nil, err
	}
	var expiresAt *time.Time
	if req.GetExpiresInDays() > 0 {
		t := time.Now().AddDate(0, 0, int(req.GetExpiresInDays()))
		expiresAt = &t
	}
	res, err := s.core.IssueMachineToken(ctx, uint(req.GetProjectId()), uint(req.GetMachineId()), req.GetName(), expiresAt, req.GetClassification(), user.UserID, nil)
	if err != nil {
		return nil, mapMachineError(err)
	}
	return &pb.IssueMachineTokenResponse{
		Token:          res.PlainToken,
		Id:             intToU32(int(res.Credential.ID)),
		Prefix:         res.Credential.TokenPrefix,
		ExpiresAt:      timePtrToTs(res.Credential.ExpiresAt),
		Classification: res.Credential.Classification,
	}, nil
}

func (s *MachineIdentityGRPCService) ListMachineTokens(ctx context.Context, req *pb.ListMachineTokensRequest) (*pb.ListMachineTokensResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetProjectId() == 0 || req.GetMachineId() == 0 {
		return nil, status.Error(codes.InvalidArgument, errProjectAndMachineRequired)
	}
	if err := authorizeScoped(ctx, s.core, user, "users.read", core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {
		return nil, err
	}
	rows, err := s.core.ListMachineTokens(ctx, uint(req.GetProjectId()), uint(req.GetMachineId()))
	if err != nil {
		return nil, mapMachineError(err)
	}
	out := make([]*pb.MachineToken, 0, len(rows))
	for _, c := range rows {
		out = append(out, machineTokenToProto(c))
	}
	return &pb.ListMachineTokensResponse{Tokens: out}, nil
}

func (s *MachineIdentityGRPCService) RevokeMachineToken(ctx context.Context, req *pb.RevokeMachineTokenRequest) (*emptypb.Empty, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetProjectId() == 0 || req.GetMachineId() == 0 || req.GetTokenId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "project_id, machine_id and token_id are required")
	}
	if err := authorizeScoped(ctx, s.core, user, permRolesAssign, core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {
		return nil, err
	}
	// gRPC has no auth cache (the interceptor validates every request), so the returned
	// hash needs no eviction here.
	if _, err := s.core.RevokeMachineToken(ctx, uint(req.GetProjectId()), uint(req.GetMachineId()), uint(req.GetTokenId()), user.UserID); err != nil {
		return nil, mapMachineError(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *MachineIdentityGRPCService) ClassifyMachineToken(ctx context.Context, req *pb.ClassifyMachineTokenRequest) (*pb.MachineToken, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetProjectId() == 0 || req.GetMachineId() == 0 || req.GetTokenId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "project_id, machine_id and token_id are required")
	}
	if err := authorizeScoped(ctx, s.core, user, permRolesAssign, core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {
		return nil, err
	}
	cred, err := s.core.ClassifyMachineToken(ctx, uint(req.GetProjectId()), uint(req.GetMachineId()), uint(req.GetTokenId()), req.GetClassification(), user.UserID)
	if err != nil {
		return nil, mapMachineError(err)
	}
	return machineTokenToProto(cred), nil
}

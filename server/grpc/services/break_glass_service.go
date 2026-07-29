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

// BreakGlassGRPCService implements pb.BreakGlassServiceServer over the shared core. It
// enforces the SAME authorization as the HTTP routes: activate is self-service (any
// authenticated member — it must work in an emergency), list → scoped roles.read,
// revoke → scoped roles.assign. core audits every activation and revoke.
type BreakGlassGRPCService struct {
	pb.UnimplementedBreakGlassServiceServer
	core *core.KeyorixCore
}

var _ pb.BreakGlassServiceServer = (*BreakGlassGRPCService)(nil)

// NewBreakGlassService creates a break-glass gRPC service backed by the shared core.
func NewBreakGlassService(coreService *core.KeyorixCore) *BreakGlassGRPCService {
	return &BreakGlassGRPCService{core: coreService}
}

// ActivateBreakGlass grants the caller emergency access on a project. Self-service:
// any authenticated user may activate (mirrors the HTTP route, which gates on auth
// only — emergency access must not depend on a permission the incident may have
// removed). The activation is time-bound and audited by core.
func (s *BreakGlassGRPCService) ActivateBreakGlass(ctx context.Context, req *pb.ActivateBreakGlassRequest) (*pb.BreakGlassActivation, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	a, err := s.core.ActivateBreakGlass(ctx, uint(req.GetProjectId()), actor.UserID, req.GetJustification(), req.GetTtl())
	if err != nil {
		return nil, breakGlassError(err)
	}
	return breakGlassToProto(a), nil
}

// ListBreakGlassActivations lists a project's activations. Requires scoped roles.read.
func (s *BreakGlassGRPCService) ListBreakGlassActivations(ctx context.Context, req *pb.ListBreakGlassActivationsRequest) (*pb.ListBreakGlassActivationsResponse, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeScoped(ctx, s.core, actor, "roles.read", core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {
		return nil, err
	}
	acts, err := s.core.ListBreakGlassActivations(ctx, uint(req.GetProjectId()))
	if err != nil {
		return nil, breakGlassError(err)
	}
	out := make([]*pb.BreakGlassActivation, 0, len(acts))
	for _, a := range acts {
		out = append(out, breakGlassToProto(a))
	}
	return &pb.ListBreakGlassActivationsResponse{Activations: out}, nil
}

// RevokeBreakGlass ends an active activation early. Requires scoped roles.assign.
func (s *BreakGlassGRPCService) RevokeBreakGlass(ctx context.Context, req *pb.RevokeBreakGlassRequest) (*emptypb.Empty, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeScoped(ctx, s.core, actor, "roles.assign", core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {
		return nil, err
	}
	if err := s.core.RevokeBreakGlass(ctx, actor.UserID, uint(req.GetProjectId()), uint(req.GetActivationId())); err != nil {
		return nil, breakGlassError(err)
	}
	return &emptypb.Empty{}, nil
}

func breakGlassToProto(a *models.BreakGlassActivation) *pb.BreakGlassActivation {
	out := &pb.BreakGlassActivation{
		Id:            intToU32(int(a.ID)),
		ProjectId:     intToU32(int(a.ProjectID)),
		UserId:        intToU32(int(a.UserID)),
		RoleId:        intToU32(int(a.RoleID)),
		RoleName:      a.RoleName,
		Justification: a.Justification,
		State:         a.State,
		CreatedAt:     timestamppb.New(a.CreatedAt),
	}
	if a.ExpiresAt != nil {
		out.ExpiresAt = timestamppb.New(*a.ExpiresAt)
	}
	if a.RevokedBy != 0 {
		out.RevokedBy = ptrU32(a.RevokedBy)
	}
	if a.RevokedAt != nil {
		out.RevokedAt = timestamppb.New(*a.RevokedAt)
	}
	return out
}

// breakGlassError maps a core error to a gRPC status, mirroring the HTTP status codes.
func breakGlassError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found"):
		return status.Error(codes.NotFound, "break-glass activation not found") // GRPC-005: was msg — leaked storage error details
	case strings.Contains(msg, "justification") || strings.Contains(msg, "required") || strings.Contains(msg, "invalid"):
		return status.Error(codes.InvalidArgument, "invalid request") // GRPC-005: was msg — leaked minimum justification length
	case strings.Contains(msg, "permission") || strings.Contains(msg, "denied"):
		return status.Error(codes.PermissionDenied, "access denied")
	case strings.Contains(msg, "already revoked") || strings.Contains(msg, "not active") || strings.Contains(msg, "expired"):
		return status.Error(codes.FailedPrecondition, "activation is not in a valid state for this operation") // GRPC-005: was msg
	default:
		return status.Error(codes.Internal, "break-glass operation failed")
	}
}

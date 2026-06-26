package services

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/keyorixhq/keyorix/internal/core"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// ProjectGRPCService implements pb.ProjectServiceServer, backing each RPC with the
// shared core service. It enforces the SAME permissions as the HTTP routes:
// list/get → secrets.read, create/update → secrets.write, delete → secrets.delete,
// scoped per project for per-project operations.
type ProjectGRPCService struct {
	pb.UnimplementedProjectServiceServer
	core *core.KeyorixCore
}

var _ pb.ProjectServiceServer = (*ProjectGRPCService)(nil)

// NewProjectService creates a project gRPC service backed by the shared core.
func NewProjectService(coreService *core.KeyorixCore) *ProjectGRPCService {
	return &ProjectGRPCService{core: coreService}
}

func mapProjectError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found"):
		return status.Error(codes.NotFound, "project not found")
	case strings.Contains(msg, "already exists"):
		return status.Error(codes.AlreadyExists, "a project with this name already exists")
	case strings.Contains(msg, "permission") || strings.Contains(msg, "denied"):
		return status.Error(codes.PermissionDenied, "access denied")
	default:
		return status.Error(codes.Internal, "project operation failed")
	}
}

func (s *ProjectGRPCService) ListProjects(ctx context.Context, _ *emptypb.Empty) (*pb.ListProjectsResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, user, "secrets.read"); err != nil {
		return nil, err
	}
	projects, err := s.core.ListProjects(ctx)
	if err != nil {
		return nil, mapProjectError(err)
	}
	out := make([]*pb.Project, 0, len(projects))
	for _, p := range projects {
		out = append(out, projectToProto(p))
	}
	return &pb.ListProjectsResponse{Projects: out}, nil
}

func (s *ProjectGRPCService) GetProject(ctx context.Context, req *pb.GetProjectRequest) (*pb.Project, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if err := authorizeScoped(ctx, s.core, user, "secrets.read", core.Scope{ProjectID: uint(req.GetId())}); err != nil {
		return nil, err
	}
	project, err := s.core.GetProject(ctx, uint(req.GetId()))
	if err != nil {
		return nil, mapProjectError(err)
	}
	return projectToProto(project), nil
}

// GetProjectRotationOrder returns a safe rotation sequence for the project's secret
// dependency graph (ADR-052). Requires scoped secrets.read on the project.
func (s *ProjectGRPCService) GetProjectRotationOrder(ctx context.Context, req *pb.GetProjectRequest) (*pb.RotationOrder, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if err := authorizeScoped(ctx, s.core, user, "secrets.read", core.Scope{ProjectID: uint(req.GetId())}); err != nil {
		return nil, err
	}
	order, err := s.core.GetProjectRotationOrder(ctx, uint(req.GetId()))
	if err != nil {
		return nil, mapProjectError(err)
	}
	return rotationOrderToProto(order), nil
}

// GetProjectRotationPlan returns the project's automated rotation plan (ADR-053).
// Requires scoped secrets.read on the project.
func (s *ProjectGRPCService) GetProjectRotationPlan(ctx context.Context, req *pb.GetProjectRequest) (*pb.RotationPlan, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if err := authorizeScoped(ctx, s.core, user, "secrets.read", core.Scope{ProjectID: uint(req.GetId())}); err != nil {
		return nil, err
	}
	plan, err := s.core.GenerateRotationPlan(ctx, uint(req.GetId()))
	if err != nil {
		return nil, mapProjectError(err)
	}
	return rotationPlanToProto(plan), nil
}

func (s *ProjectGRPCService) CreateProject(ctx context.Context, req *pb.CreateProjectRequest) (*pb.Project, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if err := authorizeGlobal(ctx, s.core, user, "secrets.write"); err != nil {
		return nil, err
	}
	project, err := s.core.CreateProject(ctx, req.GetName(), req.GetDescription())
	if err != nil {
		return nil, mapProjectError(err)
	}
	return projectToProto(project), nil
}

func (s *ProjectGRPCService) UpdateProject(ctx context.Context, req *pb.UpdateProjectRequest) (*pb.Project, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if err := authorizeScoped(ctx, s.core, user, "secrets.write", core.Scope{ProjectID: uint(req.GetId())}); err != nil {
		return nil, err
	}
	var requireMFA *bool
	if req.RequireMfa != nil {
		v := req.GetRequireMfa()
		requireMFA = &v
		// require_mfa is a per-project security-policy control: changing it additionally
		// requires roles.assign at the project (parity with the HTTP handler), so a
		// non-admin secrets.write holder can't silently disable MFA enforcement.
		if err := authorizeScoped(ctx, s.core, user, "roles.assign", core.Scope{ProjectID: uint(req.GetId())}); err != nil {
			return nil, err
		}
	}
	project, err := s.core.UpdateProject(ctx, uint(req.GetId()), req.GetName(), req.GetDescription(), requireMFA)
	if err != nil {
		return nil, mapProjectError(err)
	}
	return projectToProto(project), nil
}

func (s *ProjectGRPCService) DeleteProject(ctx context.Context, req *pb.DeleteProjectRequest) (*emptypb.Empty, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if err := authorizeScoped(ctx, s.core, user, "secrets.delete", core.Scope{ProjectID: uint(req.GetId())}); err != nil {
		return nil, err
	}
	if err := s.core.DeleteProject(ctx, uint(req.GetId()), req.GetForce()); err != nil {
		return nil, mapProjectError(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *ProjectGRPCService) ListEnvironments(ctx context.Context, req *pb.ListEnvironmentsRequest) (*pb.ListEnvironmentsResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetProjectId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "project_id is required")
	}
	if err := authorizeScoped(ctx, s.core, user, "secrets.read", core.Scope{ProjectID: uint(req.GetProjectId())}); err != nil {
		return nil, err
	}
	envs, err := s.core.ListEnvironmentsByProject(ctx, uint(req.GetProjectId()))
	if err != nil {
		return nil, mapProjectError(err)
	}
	out := make([]*pb.Environment, 0, len(envs))
	for _, e := range envs {
		out = append(out, environmentToProto(e))
	}
	return &pb.ListEnvironmentsResponse{Environments: out}, nil
}

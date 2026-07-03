package services

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// DynamicSecretGRPCService implements pb.DynamicSecretServiceServer (ADR-035).
// Authz mirrors the HTTP handlers: reads use secrets.read, mutations secrets.write,
// each scoped to the owning config's (or lease's) project/environment. The admin
// DSN is never returned; an issued credential is returned exactly once.
type DynamicSecretGRPCService struct {
	pb.UnimplementedDynamicSecretServiceServer
	core *core.KeyorixCore
}

var _ pb.DynamicSecretServiceServer = (*DynamicSecretGRPCService)(nil)

// NewDynamicSecretService creates the service backed by the shared core.
func NewDynamicSecretService(coreService *core.KeyorixCore) *DynamicSecretGRPCService {
	return &DynamicSecretGRPCService{core: coreService}
}

func mapDynamicError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found"):
		return status.Error(codes.NotFound, "config or lease not found")
	case strings.Contains(msg, "cannot exceed") || strings.Contains(msg, "required") || strings.Contains(msg, "classification must"):
		return status.Error(codes.InvalidArgument, msg)
	case strings.Contains(msg, "permission") || strings.Contains(msg, "denied"):
		return status.Error(codes.PermissionDenied, "access denied")
	default:
		// Issue/renew/revoke reach the target database; surface backend trouble as Unavailable.
		return status.Error(codes.Unavailable, "dynamic-secret backend operation failed")
	}
}

// loadConfigScoped loads a config by ID and authorizes perm at its project/env scope.
func (s *DynamicSecretGRPCService) loadConfigScoped(ctx context.Context, user *interceptors.UserContext, id uint, perm string) (*models.DynamicSecretConfig, error) {
	cfg, err := s.core.GetDynamicSecretConfig(ctx, id)
	if err != nil {
		return nil, status.Error(codes.NotFound, "config not found")
	}
	if err := authorizeScoped(ctx, s.core, user, perm, core.Scope{ProjectID: cfg.ProjectID, EnvironmentID: cfg.EnvironmentID}); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (s *DynamicSecretGRPCService) ListConfigs(ctx context.Context, req *pb.ListDynamicConfigsRequest) (*pb.ListDynamicConfigsResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetProjectId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "project_id is required")
	}
	if err := authorizeScoped(ctx, s.core, user, "secrets.read", core.Scope{ProjectID: uint(req.GetProjectId()), EnvironmentID: uint(req.GetEnvironmentId())}); err != nil {
		return nil, err
	}
	cfgs, err := s.core.ListDynamicSecretConfigs(ctx, uint(req.GetProjectId()), uint(req.GetEnvironmentId()))
	if err != nil {
		return nil, mapDynamicError(err)
	}
	out := make([]*pb.DynamicSecretConfig, 0, len(cfgs))
	for _, c := range cfgs {
		out = append(out, dynamicConfigToProto(c))
	}
	return &pb.ListDynamicConfigsResponse{Configs: out}, nil
}

func (s *DynamicSecretGRPCService) GetConfig(ctx context.Context, req *pb.GetDynamicConfigRequest) (*pb.DynamicSecretConfig, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	cfg, err := s.loadConfigScoped(ctx, user, uint(req.GetId()), "secrets.read")
	if err != nil {
		return nil, err
	}
	return dynamicConfigToProto(cfg), nil
}

func (s *DynamicSecretGRPCService) CreateConfig(ctx context.Context, req *pb.CreateDynamicConfigRequest) (*pb.DynamicSecretConfig, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetName() == "" || req.GetProjectId() == 0 || req.GetAdminDsn() == "" {
		return nil, status.Error(codes.InvalidArgument, "name, project_id and admin_dsn are required")
	}
	if err := authorizeScoped(ctx, s.core, user, "secrets.write", core.Scope{ProjectID: uint(req.GetProjectId()), EnvironmentID: uint(req.GetEnvironmentId())}); err != nil {
		return nil, err
	}
	cfg, err := s.core.CreateDynamicSecretConfig(ctx, &core.CreateDynamicSecretConfigRequest{
		Name:              req.GetName(),
		ProjectID:         uint(req.GetProjectId()),
		EnvironmentID:     uint(req.GetEnvironmentId()),
		BackendType:       req.GetBackendType(),
		AdminDSN:          req.GetAdminDsn(),
		CreationTemplate:  req.GetCreationTemplate(),
		DefaultTTLSeconds: int(req.GetDefaultTtlSeconds()),
		MaxTTLSeconds:     int(req.GetMaxTtlSeconds()),
		Classification:    req.GetClassification(),
		CreatedBy:         user.Username,
		ActorID:           user.PrincipalID(),
	})
	if err != nil {
		return nil, mapDynamicError(err)
	}
	return dynamicConfigToProto(cfg), nil
}

func (s *DynamicSecretGRPCService) ClassifyConfig(ctx context.Context, req *pb.ClassifyDynamicConfigRequest) (*pb.DynamicSecretConfig, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	if _, err := s.loadConfigScoped(ctx, user, uint(req.GetId()), "secrets.write"); err != nil {
		return nil, err
	}
	cfg, err := s.core.ClassifyDynamicSecretConfig(ctx, user.UserID, uint(req.GetId()), req.GetClassification())
	if err != nil {
		return nil, mapDynamicError(err)
	}
	return dynamicConfigToProto(cfg), nil
}

func (s *DynamicSecretGRPCService) IssueLease(ctx context.Context, req *pb.IssueLeaseRequest) (*pb.IssuedCredential, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetConfigId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "config_id is required")
	}
	if _, err := s.loadConfigScoped(ctx, user, uint(req.GetConfigId()), "secrets.write"); err != nil {
		return nil, err
	}
	lease, err := s.core.IssueLease(ctx, uint(req.GetConfigId()), int(req.GetTtlSeconds()), user.UserID)
	if err != nil {
		return nil, mapDynamicError(err)
	}
	return &pb.IssuedCredential{
		LeaseId:   lease.LeaseID,
		Username:  lease.Username,
		Password:  lease.Password,
		Fields:    lease.Fields,
		ExpiresAt: timestamppb.New(lease.ExpiresAt),
	}, nil
}

func (s *DynamicSecretGRPCService) ListLeases(ctx context.Context, req *pb.ListLeasesRequest) (*pb.ListLeasesResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetConfigId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "config_id is required")
	}
	if _, err := s.loadConfigScoped(ctx, user, uint(req.GetConfigId()), "secrets.read"); err != nil {
		return nil, err
	}
	leases, err := s.core.ListDynamicSecretLeases(ctx, uint(req.GetConfigId()))
	if err != nil {
		return nil, mapDynamicError(err)
	}
	out := make([]*pb.DynamicSecretLease, 0, len(leases))
	for _, l := range leases {
		out = append(out, dynamicLeaseToProto(l))
	}
	return &pb.ListLeasesResponse{Leases: out}, nil
}

// loadLeaseScoped loads a lease by its opaque ID and authorizes perm at its scope.
func (s *DynamicSecretGRPCService) loadLeaseScoped(ctx context.Context, user *interceptors.UserContext, leaseID, perm string) (*models.DynamicSecretLease, error) {
	lease, err := s.core.GetDynamicSecretLease(ctx, leaseID)
	if err != nil {
		return nil, status.Error(codes.NotFound, "lease not found")
	}
	if err := authorizeScoped(ctx, s.core, user, perm, core.Scope{ProjectID: lease.ProjectID, EnvironmentID: lease.EnvironmentID}); err != nil {
		return nil, err
	}
	return lease, nil
}

func (s *DynamicSecretGRPCService) RevokeLease(ctx context.Context, req *pb.RevokeLeaseRequest) (*emptypb.Empty, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetLeaseId() == "" {
		return nil, status.Error(codes.InvalidArgument, "lease_id is required")
	}
	if _, err := s.loadLeaseScoped(ctx, user, req.GetLeaseId(), "secrets.write"); err != nil {
		return nil, err
	}
	if err := s.core.RevokeLease(ctx, req.GetLeaseId(), user.UserID, "manual"); err != nil {
		return nil, mapDynamicError(err)
	}
	return &emptypb.Empty{}, nil
}

func (s *DynamicSecretGRPCService) RenewLease(ctx context.Context, req *pb.RenewLeaseRequest) (*pb.RenewLeaseResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetLeaseId() == "" {
		return nil, status.Error(codes.InvalidArgument, "lease_id is required")
	}
	if _, err := s.loadLeaseScoped(ctx, user, req.GetLeaseId(), "secrets.write"); err != nil {
		return nil, err
	}
	newExpiry, err := s.core.RenewLease(ctx, req.GetLeaseId(), int(req.GetTtlSeconds()), user.UserID)
	if err != nil {
		return nil, mapDynamicError(err)
	}
	return &pb.RenewLeaseResponse{LeaseId: req.GetLeaseId(), ExpiresAt: timestamppb.New(newExpiry)}, nil
}

func (s *DynamicSecretGRPCService) RevokeAllLeases(ctx context.Context, req *pb.RevokeAllLeasesRequest) (*pb.RevokeAllLeasesResponse, error) {
	user, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if req.GetConfigId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "config_id is required")
	}
	if _, err := s.loadConfigScoped(ctx, user, uint(req.GetConfigId()), "secrets.write"); err != nil {
		return nil, err
	}
	revoked, failed, err := s.core.RevokeLeasesForConfig(ctx, uint(req.GetConfigId()), user.UserID, "bulk")
	if err != nil {
		return nil, mapDynamicError(err)
	}
	return &pb.RevokeAllLeasesResponse{Revoked: intToU32(revoked), Failed: intToU32(failed)}, nil
}

package services

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ConnectGRPCService implements pb.ConnectServiceServer — the read-through
// federation surface over gRPC (ADR-043), mirroring the HTTP /connect routes. Both
// RPCs require an authenticated user with global connect.read (ADR-044). Values are
// proxied on demand and never persisted.
type ConnectGRPCService struct {
	pb.UnimplementedConnectServiceServer
	core *core.KeyorixCore
}

var _ pb.ConnectServiceServer = (*ConnectGRPCService)(nil)

// NewConnectService creates a connect gRPC service.
func NewConnectService(coreService *core.KeyorixCore) *ConnectGRPCService {
	return &ConnectGRPCService{core: coreService}
}

// ListConnectors returns the configured connector names.
func (s *ConnectGRPCService) ListConnectors(ctx context.Context, _ *emptypb.Empty) (*pb.ConnectorList, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, "connect.read"); err != nil {
		return nil, err
	}
	return &pb.ConnectorList{Connectors: s.core.ConnectConnectorNames()}, nil
}

// ReadSecret proxies a read-through of a secret's current value from a connector.
func (s *ConnectGRPCService) ReadSecret(ctx context.Context, req *pb.ReadFederatedSecretRequest) (*pb.FederatedSecretValue, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, "connect.read"); err != nil {
		return nil, err
	}
	value, err := s.core.ReadFederatedSecret(ctx, actor.ActorKind(), actor.PrincipalID(), req.GetConnector(), req.GetRef())
	if err != nil {
		return nil, err
	}
	return &pb.FederatedSecretValue{
		Connector: req.GetConnector(),
		Ref:       req.GetRef(),
		Value:     value,
	}, nil
}

// ListRefGrants returns all per-reference grants (ADR-045). Gated by roles.read —
// grants are role-authorization config, mirroring the HTTP /connect/ref-grants routes.
func (s *ConnectGRPCService) ListRefGrants(ctx context.Context, _ *emptypb.Empty) (*pb.ConnectRefGrantList, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, "roles.read"); err != nil {
		return nil, err
	}
	grants, err := s.core.ListConnectRefGrants(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	out := make([]*pb.ConnectRefGrant, 0, len(grants))
	for _, g := range grants {
		out = append(out, &pb.ConnectRefGrant{
			Id:        intToU32(int(g.ID)),
			RoleId:    intToU32(int(g.RoleID)),
			Connector: g.Connector,
			RefPrefix: g.RefPrefix,
		})
	}
	return &pb.ConnectRefGrantList{Grants: out}, nil
}

// CreateRefGrant adds a per-reference grant. Gated by roles.write.
func (s *ConnectGRPCService) CreateRefGrant(ctx context.Context, req *pb.CreateConnectRefGrantRequest) (*pb.ConnectRefGrant, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, "roles.write"); err != nil {
		return nil, err
	}
	g, err := s.core.CreateConnectRefGrant(ctx, actor.PrincipalID(), uint(req.GetRoleId()), req.GetConnector(), req.GetRefPrefix())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &pb.ConnectRefGrant{
		Id:        intToU32(int(g.ID)),
		RoleId:    intToU32(int(g.RoleID)),
		Connector: g.Connector,
		RefPrefix: g.RefPrefix,
	}, nil
}

// DeleteRefGrant removes a per-reference grant by id. Gated by roles.write.
func (s *ConnectGRPCService) DeleteRefGrant(ctx context.Context, req *pb.DeleteConnectRefGrantRequest) (*emptypb.Empty, error) {
	actor, err := requireUser(ctx)
	if err != nil {
		return nil, err
	}
	if err := authorizeGlobal(ctx, s.core, actor, "roles.write"); err != nil {
		return nil, err
	}
	if err := s.core.DeleteConnectRefGrant(ctx, actor.PrincipalID(), uint(req.GetId())); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &emptypb.Empty{}, nil
}

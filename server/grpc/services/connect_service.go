package services

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
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
	principalID := actor.UserID
	if actor.ActorKind() == core.ActorTypeMachine {
		principalID = actor.MachineIdentityID
	}
	value, err := s.core.ReadFederatedSecret(ctx, actor.ActorKind(), principalID, req.GetConnector(), req.GetRef())
	if err != nil {
		return nil, err
	}
	return &pb.FederatedSecretValue{
		Connector: req.GetConnector(),
		Ref:       req.GetRef(),
		Value:     value,
	}, nil
}

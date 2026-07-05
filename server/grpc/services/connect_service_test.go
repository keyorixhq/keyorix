package services

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/connect"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// fakeConnector is an in-memory connect.Connector for the gRPC service tests — it
// returns a fixed value without touching any backend.
type fakeConnector struct {
	name  string
	value string
}

func (f fakeConnector) Name() string { return f.name }
func (f fakeConnector) Type() string { return "fake" }
func (f fakeConnector) GetSecret(_ context.Context, _ string) (string, error) {
	return f.value, nil
}

func newConnectService(t *testing.T) *ConnectGRPCService {
	t.Helper()
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	// Admin-context user (id 1) = super_admin (global, holds connect.read); denied
	// tests use an ungranted user id so core.Authorize refuses them.
	h.AssignUserRole(t, 1, 1, nil)
	h.CoreService.SetConnectManager(connect.NewManager([]connect.Connector{
		fakeConnector{name: "aws", value: "s3cr3t"},
	}))
	return NewConnectService(h.CoreService)
}

func connCtx() context.Context {
	return authCtx(1, "admin", "connect.read")
}

func readReq(connector, ref string) *pb.ReadFederatedSecretRequest {
	return &pb.ReadFederatedSecretRequest{Connector: connector, Ref: ref}
}

func TestConnectService_ListConnectors(t *testing.T) {
	svc := newConnectService(t)
	list, err := svc.ListConnectors(connCtx(), &emptypb.Empty{})
	require.NoError(t, err)
	require.NotNil(t, list)
	assert.Equal(t, []string{"aws"}, list.GetConnectors())
}

func TestConnectService_ReadSecret(t *testing.T) {
	svc := newConnectService(t)
	v, err := svc.ReadSecret(connCtx(), readReq("aws", "prod/db"))
	require.NoError(t, err)
	require.NotNil(t, v)
	assert.Equal(t, "aws", v.GetConnector())
	assert.Equal(t, "prod/db", v.GetRef())
	assert.Equal(t, "s3cr3t", v.GetValue())
}

func TestConnectService_ReadSecret_UnknownConnector(t *testing.T) {
	svc := newConnectService(t)
	_, err := svc.ReadSecret(connCtx(), readReq("nope", "x"))
	require.Error(t, err)
}

// TestConnectService_ReadSecret_EmptyRefRejected regression-tests backlog #400:
// ReadSecret must reject an empty ref with codes.InvalidArgument before ever
// calling core.ReadFederatedSecret, matching the HTTP GetSecret handler's
// `ref query parameter is required` 400 (server/http/handlers/connect.go).
func TestConnectService_ReadSecret_EmptyRefRejected(t *testing.T) {
	svc := newConnectService(t)
	_, err := svc.ReadSecret(connCtx(), readReq("aws", ""))
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestConnectService_Unauthenticated(t *testing.T) {
	svc := newConnectService(t)
	_, err := svc.ListConnectors(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	_, err = svc.ReadSecret(context.Background(), readReq("aws", "x"))
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestConnectService_PermissionDenied(t *testing.T) {
	svc := newConnectService(t)
	ctx := authCtx(7, "nobody") // ungranted user → denied
	_, err := svc.ListConnectors(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = svc.ReadSecret(ctx, readReq("aws", "x"))
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// --- Per-reference grant management (ADR-045) ---

func TestConnectService_RefGrants_CRUD(t *testing.T) {
	svc := newConnectService(t)
	ctx := authCtx(1, "admin", "roles.write")

	// Empty to start.
	list, err := svc.ListRefGrants(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.Empty(t, list.GetGrants())

	// Create one for an existing connector.
	g, err := svc.CreateRefGrant(ctx, &pb.CreateConnectRefGrantRequest{RoleId: 5, Connector: "aws", RefPrefix: "metrics/"})
	require.NoError(t, err)
	assert.NotZero(t, g.GetId())
	assert.Equal(t, uint32(5), g.GetRoleId())
	assert.Equal(t, "aws", g.GetConnector())
	assert.Equal(t, "metrics/", g.GetRefPrefix())

	// It now lists.
	list, err = svc.ListRefGrants(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	require.Len(t, list.GetGrants(), 1)

	// Delete it.
	_, err = svc.DeleteRefGrant(ctx, &pb.DeleteConnectRefGrantRequest{Id: g.GetId()})
	require.NoError(t, err)
	list, err = svc.ListRefGrants(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.Empty(t, list.GetGrants())
}

func TestConnectService_RefGrants_UnknownConnectorRejected(t *testing.T) {
	svc := newConnectService(t)
	_, err := svc.CreateRefGrant(authCtx(1, "admin", "roles.write"),
		&pb.CreateConnectRefGrantRequest{RoleId: 5, Connector: "nope", RefPrefix: "x/"})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestConnectService_RefGrants_Unauthenticated(t *testing.T) {
	svc := newConnectService(t)
	_, err := svc.ListRefGrants(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	_, err = svc.CreateRefGrant(context.Background(), &pb.CreateConnectRefGrantRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestConnectService_RefGrants_PermissionDenied(t *testing.T) {
	svc := newConnectService(t)
	// connect.read alone (held via super_admin in other tests) is not roles.write;
	// an ungranted user is denied outright.
	ctx := authCtx(7, "nobody")
	_, err := svc.ListRefGrants(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = svc.CreateRefGrant(ctx, &pb.CreateConnectRefGrantRequest{RoleId: 5, Connector: "aws", RefPrefix: "x/"})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	_, err = svc.DeleteRefGrant(ctx, &pb.DeleteConnectRefGrantRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

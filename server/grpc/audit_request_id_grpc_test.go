// audit_request_id_grpc_test.go — AUDIT-REQUEST-ID-2 item 2: audit rows written by a
// gRPC call carry the request id the server minted for that call, and a client-supplied
// x-request-id never reaches audit_events.request_id (docs/specs/audit-request-id.md).
// Driven through the REAL gRPC server (keyorixgrpc.NewServer, bufconn), like
// secrets_machine_attribution_grpc_test.go.
package grpc_test

import (
	"context"
	"net"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	"github.com/keyorixhq/keyorix/server/grpc/services"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

var grpcServerRequestID = regexp.MustCompile(`^[0-9a-f]{24}$`)

func dialCore(t *testing.T, c *core.KeyorixCore) *grpc.ClientConn {
	t.Helper()
	srv, err := keyorixgrpc.NewServer(&config.Config{}, c)
	require.NoError(t, err)
	lis := bufconn.Listen(1024 * 1024)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestGRPCMutation_AuditRowCarriesServerMintedRequestID(t *testing.T) {
	secrets, machineToken, secretID, c, _, _ := grpcMachineAttributionFixture(t)

	const clientChosen = "client-chosen-grpc-id-001"
	newValue := "v2-request-id"
	var header metadata.MD
	ctx := metadata.AppendToOutgoingContext(bearerCtx(machineToken), interceptors.RequestIDMetadataKey, clientChosen)
	_, err := secrets.UpdateSecret(ctx, &pb.UpdateSecretRequest{Id: uint32(secretID), Value: &newValue}, grpc.Header(&header))
	require.NoError(t, err)

	// The call's response headers carry the server's id, never the client's.
	ids := header.Get(interceptors.RequestIDMetadataKey)
	require.Len(t, ids, 1, "response header %s", interceptors.RequestIDMetadataKey)
	serverID := ids[0]
	require.Regexp(t, grpcServerRequestID, serverID)
	require.NotEqual(t, clientChosen, serverID)

	services.DrainBackgroundGoroutines()
	core.DrainBackgroundGoroutines()

	// The mutation's audit row carries exactly that id.
	events, _, err := c.Storage().GetAuditLogs(context.Background(), &coreStorage.AuditFilter{SecretID: &secretID, PageSize: 20})
	require.NoError(t, err)
	ev := findGRPCAuditEvent(events, "secret.updated")
	require.NotNil(t, ev, "expected a secret.updated audit event")
	require.NotNil(t, ev.RequestID, "a gRPC mutation's audit row must carry a request id (NULL before the interceptor)")
	assert.Equal(t, serverID, *ev.RequestID)

	// The client-supplied value is on no row.
	byClient, _, err := c.Storage().GetAuditLogs(context.Background(), &coreStorage.AuditFilter{RequestID: ptrString(clientChosen), PageSize: 20})
	require.NoError(t, err)
	assert.Empty(t, byClient, "a client-chosen x-request-id must never reach audit_events.request_id")
	for _, e := range events {
		if e.RequestID != nil {
			assert.NotEqual(t, clientChosen, *e.RequestID)
		}
	}

	// AuditService: the id is on the entry and the filter finds the row.
	sess, _, err := c.Login(context.Background(), &core.LoginRequest{Username: "testadmin", Password: "TestPassword123!"})
	require.NoError(t, err)
	audit := pb.NewAuditServiceClient(dialCore(t, c))
	resp, err := audit.GetAuditLogs(bearerCtx(sess.SessionToken), &pb.GetAuditLogsRequest{RequestId: &serverID})
	require.NoError(t, err)
	require.NotEmpty(t, resp.Logs)
	for _, l := range resp.Logs {
		require.NotNil(t, l.RequestId)
		assert.Equal(t, serverID, l.GetRequestId(), "the filter is an exact match")
	}
	var sawUpdate bool
	for _, l := range resp.Logs {
		sawUpdate = sawUpdate || l.EventType == "secret.updated"
	}
	assert.True(t, sawUpdate, "the filtered list holds the mutation's row")

	none, err := audit.GetAuditLogs(bearerCtx(sess.SessionToken), &pb.GetAuditLogsRequest{RequestId: ptrString(clientChosen)})
	require.NoError(t, err)
	assert.Empty(t, none.Logs)
}

func ptrString(s string) *string { return &s }

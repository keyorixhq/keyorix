package grpc_test

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

// TestGRPCServer_EndToEnd drives the real NewServer wiring (all six services +
// the real auth interceptor) over an in-process bufconn connection. Unlike the
// per-service unit tests (which inject the user context directly), this exercises
// the full path: bearer token in metadata → interceptor validates the session →
// resolves RBAC permissions → service → core.
func TestGRPCServer_EndToEnd(t *testing.T) {
	const token = "e2e-session-token"

	// Real core with a fully seeded RBAC schema (super_admin has all perms).
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	require.NoError(t, h.DB.AutoMigrate(&models.Session{}, &models.SecretVersion{}, &models.AuditEvent{}, &models.SecretAccessLog{}))
	// The services fire their audit/access-log writes in detached goroutines (as on
	// HTTP), so serialize the in-memory DB to one connection to avoid SQLite
	// "database is locked" races between those writes and the test's own RPCs.
	sqlDB, sqlErr := h.DB.DB()
	require.NoError(t, sqlErr)
	sqlDB.SetMaxOpenConns(1)
	// Environments that belong to the seeded projects 1 and 2 (seeded envs have none).
	require.NoError(t, h.DB.Create(&models.Environment{ID: 10, ProjectID: 1, Name: "dev"}).Error)
	require.NoError(t, h.DB.Create(&models.Environment{ID: 20, ProjectID: 2, Name: "dev"}).Error)

	// A user with the super_admin role (role id 1), and a live session token.
	user := h.CreateTestUser(t, "e2e-admin", 100)
	h.AssignUserRole(t, user.ID, 1, nil)
	expires := time.Now().Add(time.Hour)
	_, err := h.Storage.CreateSession(context.Background(), &models.Session{
		UserID: user.ID, SessionToken: token, ExpiresAt: &expires,
	})
	require.NoError(t, err)

	// A project-1-scoped writer: the "editor" role (id 3) grants secrets.write, but
	// the grant is scoped to project 1 only. Crucially, this user's FLAT permission
	// set (what the interceptor resolves and what the old gRPC handler checked) still
	// advertises secrets.write with no scope — so a wire-level test is the real proof
	// that creation is gated on the scoped check, not the flat list.
	const scopedToken = "e2e-scoped-token"
	project1 := uint(1)
	scopedWriter := h.CreateTestUser(t, "e2e-scoped-writer", 200)
	h.AssignUserRole(t, scopedWriter.ID, 3, &project1) // editor @ project 1 only
	_, err = h.Storage.CreateSession(context.Background(), &models.Session{
		UserID: scopedWriter.ID, SessionToken: scopedToken, ExpiresAt: &expires,
	})
	require.NoError(t, err)

	// Start the real server (TLS/reflection off by zero-value config) on bufconn.
	srv, err := keyorixgrpc.NewServer(&config.Config{}, h.CoreService)
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	authedCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))
	scopedCtx := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+scopedToken))

	t.Run("HealthCheck is public (no token)", func(t *testing.T) {
		resp, err := pb.NewSystemServiceClient(conn).HealthCheck(ctx, &emptypb.Empty{})
		require.NoError(t, err)
		assert.Equal(t, "healthy", resp.GetStatus())
	})

	secrets := pb.NewSecretServiceClient(conn)

	t.Run("CreateSecret without a token is rejected by the interceptor", func(t *testing.T) {
		_, err := secrets.CreateSecret(ctx, &pb.CreateSecretRequest{
			Name: "x", Value: "y", ProjectId: 1, EnvironmentId: 10, Type: "password",
		})
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	var createdID uint32
	t.Run("CreateSecret with a valid session token succeeds end-to-end", func(t *testing.T) {
		sec, err := secrets.CreateSecret(authedCtx, &pb.CreateSecretRequest{
			Name: "e2e-secret", Value: "s3cr3t", ProjectId: 1, EnvironmentId: 10, Type: "password",
		})
		require.NoError(t, err)
		assert.NotZero(t, sec.GetId())
		assert.Equal(t, "e2e-secret", sec.GetName())
		assert.Equal(t, uint32(1), sec.GetProjectId())
		createdID = sec.GetId()
	})

	t.Run("GetSecret with a valid session token returns it", func(t *testing.T) {
		sec, err := secrets.GetSecret(authedCtx, &pb.GetSecretRequest{Id: createdID})
		require.NoError(t, err)
		assert.Equal(t, "e2e-secret", sec.GetName())
	})

	// Scoped-authz regression (extends the #54 unit fix to the wire). The scoped
	// writer holds secrets.write only at project 1. Through the real interceptor
	// stack — session validated → flat RBAC permissions resolved → service — the
	// CreateSecret scope check must allow creation in project 1 and deny it in
	// project 2, even though the resolved flat permission set advertises
	// secrets.write globally.
	t.Run("scoped writer can create within its project", func(t *testing.T) {
		sec, err := secrets.CreateSecret(scopedCtx, &pb.CreateSecretRequest{
			Name: "in-scope", Value: "v", ProjectId: 1, EnvironmentId: 10, Type: "password",
		})
		require.NoError(t, err)
		assert.Equal(t, uint32(1), sec.GetProjectId())
	})

	t.Run("scoped writer is denied creating in another project", func(t *testing.T) {
		_, err := secrets.CreateSecret(scopedCtx, &pb.CreateSecretRequest{
			Name: "cross-project", Value: "v", ProjectId: 2, EnvironmentId: 20, Type: "password",
		})
		require.Error(t, err)
		assert.Equal(t, codes.PermissionDenied, status.Code(err),
			"a project-1-scoped writer must not create secrets in project 2 over gRPC")
	})
}

// TestGRPCServer_HonorsConfiguredMaxRecvMsgSize proves the gRPC server enforces the
// configured request-size cap (server.grpc.max_request_body_bytes) the way the HTTP
// MaxBodyBytes middleware does — a memory-exhaustion DoS control that must not be
// bypassable by switching transport. Before the fix, NewServer ignored the setting
// and kept grpc-go's 4 MiB default.
func TestGRPCServer_HonorsConfiguredMaxRecvMsgSize(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)

	cfg := &config.Config{}
	cfg.Server.GRPC.MaxRequestBodyBytes = 4096 // 4 KiB — far below grpc-go's 4 MiB default

	srv, err := keyorixgrpc.NewServer(cfg, h.CoreService)
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	authed := metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer bogus"))
	secrets := pb.NewSecretServiceClient(conn)

	// A request over the cap is refused at the transport layer with ResourceExhausted —
	// before the auth interceptor even runs.
	_, err = secrets.CreateSecret(authed, &pb.CreateSecretRequest{
		Name: "big", Value: strings.Repeat("A", 8192), ProjectId: 1, EnvironmentId: 1, Type: "password",
	})
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err),
		"a request over the configured gRPC body cap must be rejected with ResourceExhausted")

	// A small request clears the size check and reaches auth (rejected as Unauthenticated
	// for the bogus token), proving the prior failure was the size cap and not auth.
	_, err = secrets.CreateSecret(authed, &pb.CreateSecretRequest{
		Name: "small", Value: "tiny", ProjectId: 1, EnvironmentId: 1, Type: "password",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err),
		"a small request clears the size cap and is then rejected by auth")
}

// TestGRPCServer_KeepaliveReclaimsAbandonedConnection proves grpc.KeepaliveParams is
// actually wired from server.grpc.keepalive (#222/#435), not just constructed and
// discarded: an abandoned connection — one that never sends another frame and never
// ACKs a keepalive ping, exactly the "credential holder opens a connection and never
// closes it" scenario the finding describes — must be detected and torn down within
// Time+Timeout, rather than held open indefinitely (the pre-fix behavior, a slow-drip
// goroutine/fd exhaustion surface).
//
// A real grpc-go client can't be used to simulate this: its HTTP/2 transport always
// ACKs pings automatically regardless of the client's own keepalive settings, so it
// can never look "dead" to the server. Instead this dials a raw net.Conn, completes
// just enough of the HTTP/2 handshake (client preface + an empty SETTINGS frame) to
// pass the server's handshake, and then goes silent — never reading, never writing,
// never ACKing. That is a faithful stand-in for an abandoned connection, and the
// server closing it (observed as the raw conn's Read unblocking with EOF/reset) is a
// genuine behavioral proof of the configured Time/Timeout keepalive, not just a
// construction check.
func TestGRPCServer_KeepaliveReclaimsAbandonedConnection(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)

	cfg := &config.Config{}
	// 1s is the floor grpc-go enforces on the server's keepalive Time (values below it
	// are silently raised with a warning), so this is the fastest this is practically
	// observable; Timeout is independent and can be shorter.
	cfg.Server.GRPC.Keepalive.Time = "1s"
	cfg.Server.GRPC.Keepalive.Timeout = "500ms"

	srv, err := keyorixgrpc.NewServer(cfg, h.CoreService)
	require.NoError(t, err)
	lis := bufconn.Listen(1024 * 1024)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	raw, err := lis.Dial()
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })

	// Minimal HTTP/2 handshake: client preface + an empty SETTINGS frame (required
	// before the server will treat this as a valid connection), then nothing else —
	// no reads, no writes, no ping ACKs, ever.
	_, err = raw.Write([]byte(http2.ClientPreface))
	require.NoError(t, err)
	require.NoError(t, http2.NewFramer(raw, raw).WriteSettings())

	// The server must notice the silence, ping, get no ACK within Timeout, and close
	// the connection well before our own read deadline (Time + Timeout + generous
	// slack). Drain and discard whatever the server sends (its own SETTINGS frame,
	// SETTINGS ACK, keepalive PINGs, GOAWAY, ...) without ever writing another byte
	// ourselves — an abandoned connection reads nothing back either — until the read
	// finally errors out because the server tore the connection down.
	require.NoError(t, raw.SetReadDeadline(time.Now().Add(5*time.Second)))
	buf := make([]byte, 256)
	var readErr error
	for readErr == nil {
		_, readErr = raw.Read(buf)
	}
	assert.False(t, errors.Is(readErr, os.ErrDeadlineExceeded),
		"the read must unblock because the SERVER closed the connection, not because our own read deadline fired first (got: %v)", readErr)
}

// TestGRPCServer_MetricsRecordAuthRejectedRequest is the regression guard for #223:
// MetricsInterceptor must sit outside (wrap) AuthInterceptor in the real chain
// NewServer builds, so an auth-rejected call is still counted — mirroring the HTTP
// API, where PrometheusMiddleware is registered ahead of the Authentication
// middleware and so records every request regardless of auth outcome. Before the
// fix, MetricsInterceptor ran last (after AuthInterceptor), so a request AuthInterceptor
// rejected never reached it and was invisible to keyorix_grpc_requests_total — a
// credential-stuffing campaign against the gRPC endpoint produced zero movement in
// Prometheus-based alerting.
func TestGRPCServer_MetricsRecordAuthRejectedRequest(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)

	srv, err := keyorixgrpc.NewServer(&config.Config{}, h.CoreService)
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	before := interceptors.GetGRPCMetrics()

	// No authorization metadata at all — AuthInterceptor rejects this with
	// Unauthenticated before the handler ever runs.
	_, err = pb.NewSecretServiceClient(conn).GetSecret(ctx, &pb.GetSecretRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	after := interceptors.GetGRPCMetrics()
	assert.Greater(t, after.TotalRequests, before.TotalRequests,
		"an auth-rejected request must still be counted in TotalRequests")
	assert.Greater(t, after.ErrorRequests, before.ErrorRequests,
		"an auth-rejected request must be recorded as an error outcome")
}

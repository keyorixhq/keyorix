package grpc_test

// auth_interceptor_completeness_test.go — INV-GRPC-07 (#2522).
//
// Invariant: AuthInterceptor / StreamAuthInterceptor authenticate every RPC the
// server registers, except an explicit, short public allowlist.
//
// How completeness is established: the method set is NOT a hand-maintained
// list. It is read from the real server NewServer builds
// (grpc.Server.GetServiceInfo), so a service or method added to server.go or
// to the .proto is enumerated automatically. Every method — unary and
// streaming — is then actually invoked over bufconn with no authorization
// metadata, and the rejection must be the interceptor's own
// "Missing authorization header" Unauthenticated status (a string produced
// only by interceptors.authenticateRequest — a service-level "no user in
// context" fallback answering Unauthenticated would NOT satisfy this, so the
// test fails if the interceptor is dropped from either chain even where a
// service has its own defence in depth). The public set is pinned here
// behaviourally rather than read from interceptors.grpcPublicMethods: a method
// that stops requiring auth for ANY reason (allowlist growth, chain change,
// a registration that bypasses the chain) fails, and growing the public set
// needs a deliberate edit to expectedPublicGRPCMethods.
//
// What this does NOT cover: whether authentication is followed by the right
// AUTHORIZATION check per method (that is per-service, and the protoreflect
// fuzzer's zero-grant oracle, INV-GRPC-04); and grpcPublicMethods'
// "/grpc.health.v1.Health/Check" entry, which names a service NewServer does
// not register today (so it is not enumerated here and allows nothing).

import (
	"context"
	"net"
	"sort"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	keyorixgrpc "github.com/keyorixhq/keyorix/server/grpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

// expectedPublicGRPCMethods is every registered RPC that may be reached without
// a credential. Adding to it is a security decision — mirror it in
// interceptors.grpcPublicMethods and justify it in review.
var expectedPublicGRPCMethods = map[string]bool{
	"/keyorix.v1.SystemService/HealthCheck": true, // liveness probe
}

// interceptorMissingAuthMsg is authenticateRequest's status message for a
// request with metadata but no authorization header — the proof the request
// was rejected by the auth interceptor itself, not by a downstream service.
const interceptorMissingAuthMsg = "Missing authorization header"

func TestEveryNonPublicGRPCMethod_IsRejectedByAuthInterceptor(t *testing.T) {
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

	type rpc struct {
		full   string
		stream bool
		client bool
	}
	var rpcs []rpc
	services := srv.GetServiceInfo()
	for svc, info := range services {
		for _, m := range info.Methods {
			rpcs = append(rpcs, rpc{full: "/" + svc + "/" + m.Name, stream: m.IsServerStream || m.IsClientStream, client: m.IsClientStream})
		}
	}
	sort.Slice(rpcs, func(i, j int) bool { return rpcs[i].full < rpcs[j].full })

	// Not vacuous: NewServer registers 13 services today with 86 RPCs between
	// them, including at least one stream.
	require.GreaterOrEqual(t, len(services), 13, "enumeration found fewer services than NewServer registers")
	require.GreaterOrEqual(t, len(rpcs), 80, "enumeration found implausibly few RPCs")
	var streams int
	for _, r := range rpcs {
		if r.stream {
			streams++
		}
	}
	require.Positive(t, streams, "enumeration must include the streaming RPCs (StreamAuthInterceptor's chain)")

	call := func(r rpc) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// An empty message encodes to zero bytes, which decodes as the zero value
		// of any request type, so one request shape reaches every handler.
		if !r.stream {
			return conn.Invoke(ctx, r.full, &emptypb.Empty{}, &emptypb.Empty{})
		}
		st, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true, ClientStreams: r.client}, r.full)
		if err != nil {
			return err
		}
		if err := st.SendMsg(&emptypb.Empty{}); err != nil {
			return st.RecvMsg(&emptypb.Empty{})
		}
		_ = st.CloseSend()
		return st.RecvMsg(&emptypb.Empty{})
	}

	seenPublic := map[string]bool{}
	for _, r := range rpcs {
		err := call(r)
		st := status.Convert(err)
		rejectedByInterceptor := st.Code() == codes.Unauthenticated && st.Message() == interceptorMissingAuthMsg
		if expectedPublicGRPCMethods[r.full] {
			seenPublic[r.full] = true
			assert.Falsef(t, rejectedByInterceptor, "%s is expected to be public but the auth interceptor rejected it", r.full)
			continue
		}
		assert.Truef(t, rejectedByInterceptor,
			"%s (stream=%v) was not rejected by the auth interceptor with no credential: got code=%s msg=%q — either it bypasses AuthInterceptor/StreamAuthInterceptor or it was added to grpcPublicMethods without updating expectedPublicGRPCMethods",
			r.full, r.stream, st.Code(), st.Message())
	}
	for m := range expectedPublicGRPCMethods {
		assert.Truef(t, seenPublic[m], "expected public method %s is not registered — remove it from expectedPublicGRPCMethods", m)
	}
}

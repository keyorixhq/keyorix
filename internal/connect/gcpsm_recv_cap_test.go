package connect

// gcpsm_recv_cap_test.go — proves gcpMaxRecvMsgSize (gcpsm.go) actually bounds
// what GCPSecretManagerConnector's real (non-test) client path will buffer for a
// single AccessSecretVersion response.
//
// Why this can't be tested through GetSecret/c.newClient: that seam (used by
// gcpsm_response_fuzz_test.go) injects a client built via option.WithGRPCConn,
// which bypasses grpc-go's dial-option processing entirely (confirmed by reading
// google.golang.org/api/transport/grpc/dial.go's DialPool: `if o.GRPCConn != nil
// { return &singleConnPool{o.GRPCConn}, nil }` returns before any DialOption,
// including MaxCallRecvMsgSize, is ever applied) -- so it cannot exercise this
// cap at all, in either direction. client()'s real fallback branch
// (secretmanager.NewClient(ctx) with no WithGRPCConn) does dial for real, but
// doing so needs Application Default Credentials this sandbox doesn't have.
//
// Testable without ADC by proving the underlying mechanism directly with raw
// grpc-go: dial the same way client()'s fallback composes its options (append
// grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(N)) onto a DialOptions
// list that already carries Google's own math.MaxInt32 default), against a fake
// server that returns a payload between the two caps, using the low-level
// secretmanagerpb client directly (bufconn + insecure creds, no ADC touched).
// grpc-go resolves repeated MaxCallRecvMsgSize call options last-value-wins
// (confirmed by reading grpc-go's callInfo.applyOptions), which is exactly the
// mechanism gcpMaxRecvMsgSize's placement in client() depends on.
import (
	"context"
	"math"
	"net"
	"testing"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestGCPSMMaxRecvMsgSize(t *testing.T) {
	// A payload strictly between the fix's 1 MiB cap and grpc-go's own built-in
	// 4 MiB client default -- large enough that grpc-go's unmodified default
	// would still accept it (so a pass here is attributable to the explicit cap,
	// not to grpc-go's baseline), small enough to keep the test fast.
	const oversizedPayload = 2 << 20 // 2 MiB

	dial := func(t *testing.T, extraCallOpts ...grpc.DialOption) secretmanagerpb.SecretManagerServiceClient {
		t.Helper()
		lis := bufconn.Listen(1 << 24) // large enough to carry a 2 MiB frame
		t.Cleanup(func() { _ = lis.Close() })

		srv := grpc.NewServer()
		fake := &fakeSecretManagerServer{}
		fake.setResponse(codes.OK, "", make([]byte, oversizedPayload), "projects/p/secrets/db/versions/1")
		secretmanagerpb.RegisterSecretManagerServiceServer(srv, fake)
		go func() { _ = srv.Serve(lis) }()
		t.Cleanup(srv.Stop)

		dialOpts := []grpc.DialOption{
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			// Mirrors Google's own defaultGRPCClientOptions() dial option, applied
			// first -- exactly what secretmanager.NewClient prepends today.
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(math.MaxInt32)),
		}
		dialOpts = append(dialOpts, extraCallOpts...)

		conn, err := grpc.NewClient("passthrough:///bufnet", dialOpts...)
		if err != nil {
			t.Fatalf("grpc.NewClient: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return secretmanagerpb.NewSecretManagerServiceClient(conn)
	}

	t.Run("RED: Google SDK's math.MaxInt32 default alone accepts an oversized response unbounded", func(t *testing.T) {
		cl := dial(t) // no override -- reproduces the pre-fix client() behavior
		resp, err := cl.AccessSecretVersion(context.Background(), &secretmanagerpb.AccessSecretVersionRequest{
			Name: "projects/p/secrets/db/versions/1",
		})
		if err != nil {
			t.Fatalf("expected the uncapped default to accept a %d-byte payload, got error: %v", oversizedPayload, err)
		}
		if got := len(resp.GetPayload().GetData()); got != oversizedPayload {
			t.Fatalf("expected %d-byte payload through, got %d", oversizedPayload, got)
		}
	})

	t.Run("GREEN: gcpMaxRecvMsgSize rejects the same oversized response", func(t *testing.T) {
		// Appended AFTER the math.MaxInt32 default, exactly as client() does via
		// its own option.WithGRPCDialOption(...) argument to secretmanager.NewClient.
		cl := dial(t, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(gcpMaxRecvMsgSize)))
		_, err := cl.AccessSecretVersion(context.Background(), &secretmanagerpb.AccessSecretVersionRequest{
			Name: "projects/p/secrets/db/versions/1",
		})
		if err == nil {
			t.Fatalf("BYPASS: expected a %d-byte response to be rejected by the %d-byte cap, got success", oversizedPayload, gcpMaxRecvMsgSize)
		}
		if status.Code(err) != codes.ResourceExhausted {
			t.Fatalf("expected codes.ResourceExhausted, got %v (%v)", status.Code(err), err)
		}
	})
}

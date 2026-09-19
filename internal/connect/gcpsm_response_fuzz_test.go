package connect

// gcpsm_response_fuzz_test.go — FuzzGCPSMConnectorResponse fuzzes what a hostile or
// broken GCP Secret Manager endpoint sends back to GCPSecretManagerConnector.GetSecret.
//
// Unlike Vault/AWS/Azure, GCP Secret Manager's client is gRPC, not HTTP/REST -- an
// httptest.Server (HTTP/1.1) can't stand in for it. Instead this target runs a
// minimal fake secretmanagerpb.SecretManagerServiceServer over an in-memory
// bufconn listener, whose AccessSecretVersion response (payload bytes, or a gRPC
// status code + message) is driven by the fuzz input, and injects a REAL
// secretmanager.Client wired to that fake via option.WithGRPCConn -- through the
// existing c.newClient seam, no production code change.
//
// No credential/content-echo oracle here (unlike the Vault/AWS/Azure targets):
// confirmed by reading the vendored client (secret_manager_client.go's
// defaultCallOptions), AccessSecretVersion's gax.CallOptions carry NO credential
// this harness's option.WithGRPCConn bypass ever attaches, and a gRPC status
// message is, by protocol design, meant to propagate to the caller (that's what
// status.Error's msg argument is for) -- unlike Vault/AWS/Azure, where the
// connector building its own error strings from ref/status and never echoing raw
// response BODY content is a real, checkable property. Asserting "response content
// must never appear in the error" here would be asserting against the gRPC error
// model itself, not a connector defect.
//
// GetSecret is called with a short (500ms) context deadline rather than
// context.Background(): AccessSecretVersion's OWN gax.CallOptions (confirmed by
// reading them directly) declare codes.Unavailable and codes.ResourceExhausted as
// retryable, with exponential backoff (2s initial, 60s max) bounded by a 60s overall
// gax.WithTimeout -- legitimate, already-bounded SDK behavior, not a Keyorix defect,
// but far longer than fuzzutil.Guard's fixed 3s budget would tolerate per input. A
// short caller-supplied deadline exercises the SAME retry path (still confirms it
// terminates on cancellation rather than hanging) while keeping each fuzz
// execution fast.
import (
	"context"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// fakeSecretManagerServer answers every AccessSecretVersion call according to the
// fuzz input: code == 0 (OK) returns payload as the secret's Data; any other code
// returns a gRPC error with that code and msg. hits counts every call, for the
// retry-bounded oracle (a).
type fakeSecretManagerServer struct {
	secretmanagerpb.UnimplementedSecretManagerServiceServer
	code    codes.Code
	msg     string
	payload []byte
	name    string
	hits    int32
}

func (s *fakeSecretManagerServer) AccessSecretVersion(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	atomic.AddInt32(&s.hits, 1)
	if s.code != codes.OK {
		return nil, status.Error(s.code, s.msg)
	}
	return &secretmanagerpb.AccessSecretVersionResponse{
		Name:    s.name,
		Payload: &secretmanagerpb.SecretPayload{Data: s.payload},
	}, nil
}

func FuzzGCPSMConnectorResponse(f *testing.F) {
	f.Add(uint32(0), []byte("s3cr3t"), "projects/p/secrets/db/versions/1", "")
	f.Add(uint32(0), []byte(nil), "projects/p/secrets/db/versions/1", "")
	f.Add(uint32(5), []byte(nil), "", "not found")          // codes.NotFound
	f.Add(uint32(7), []byte(nil), "", "permission denied")  // codes.PermissionDenied
	f.Add(uint32(8), []byte(nil), "", "resource exhausted") // codes.ResourceExhausted
	f.Add(uint32(13), []byte(nil), "", "internal")          // codes.Internal

	f.Fuzz(func(t *testing.T, rawCode uint32, payload []byte, name, msg string) {
		code := codes.Code(rawCode % 17) // codes.OK(0) .. codes.Unauthenticated(16)

		lis := bufconn.Listen(1 << 20)
		defer lis.Close()

		grpcSrv := grpc.NewServer()
		fakeSrv := &fakeSecretManagerServer{
			code:    code,
			msg:     msg,
			payload: payload,
			name:    name,
		}
		secretmanagerpb.RegisterSecretManagerServiceServer(grpcSrv, fakeSrv)
		go func() { _ = grpcSrv.Serve(lis) }()
		defer grpcSrv.Stop()

		dialCtx := context.Background()
		conn, err := grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			t.Fatalf("unexpected grpc.NewClient error: %v", err)
		}
		defer conn.Close()

		cl, err := secretmanager.NewClient(dialCtx, option.WithGRPCConn(conn))
		if err != nil {
			t.Fatalf("unexpected secretmanager.NewClient error: %v", err)
		}

		c := NewGCPSecretManagerConnector("fuzz", "p", nil)
		c.newClient = func(_ context.Context) (gcpSMAccessAPI, error) { return cl, nil }

		callCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		var val string
		fuzzutil.Guard(t.Fatalf, "GCPSecretManagerConnector.GetSecret", func() {
			val, err = c.GetSecret(callCtx, "projects/p/secrets/fuzz/versions/latest")
		})

		// Oracle (b): fail-closed, two ways --
		//  1. a non-OK gRPC status must always surface as an error.
		//  2. an OK status with an empty payload (out.GetPayload() nil or
		//     zero-length Data) must ALSO error -- matches gcpsm.go's own explicit
		//     "secret %q has no value" check.
		if code != codes.OK && err == nil {
			t.Fatalf("BYPASS: gRPC code %s treated as success, returned value %q", code, val)
		}
		if code == codes.OK && len(payload) == 0 && err == nil {
			t.Fatalf("BYPASS: empty payload treated as a successful read, returned value %q", val)
		}

		// Oracle (a): bounded work, retries. AccessSecretVersion's own gax retry
		// policy only retries codes.Unavailable/ResourceExhausted, with a 2s
		// initial backoff -- well past the 500ms callCtx deadline above, so this
		// should structurally never exceed 1 attempt for those codes either. Any
		// code driving a real retry storm would show up here regardless of which
		// codes gax's own policy actually covers.
		if h := atomic.LoadInt32(&fakeSrv.hits); h > connectRetryCeiling {
			t.Fatalf("RETRY STORM: fake gRPC service hit %d times for a single GetSecret call", h)
		}

		if n := runtime.NumGoroutine(); n > connectLeakCeiling {
			t.Fatalf("goroutine leak: %d goroutines after GCPSecretManagerConnector.GetSecret (expected O(10))", n)
		}
	})
}

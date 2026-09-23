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
// The fake server, its bufconn listener, and the gRPC client/connection are built
// ONCE per fuzz worker process and reused for every input (f.Cleanup tears them
// down when the worker exits), not rebuilt per input. An earlier version created a
// fresh grpc.NewServer()+bufconn.Listener()+grpc.NewClient()+secretmanager.Client
// on every single execution and tore them all down again via
// grpcSrv.Stop()/conn.Close()/lis.Close() before the next one -- under sustained
// fuzzing (thousands of executions/sec) this reliably leaked blocked goroutines
// that Stop()/Close() never unblocked (bufconn pipe readers parked in
// sync.Cond.Wait, HTTP/2 loopyWriter/keepalive/CallbackSerializer goroutines from
// both the client and server transport), confirmed by reproducing the same
// continuous per-iteration slowdown and goroutine accumulation OUTSIDE go test
// -fuzz entirely (a plain loop driving the same create/teardown-per-call pattern).
// That leak is what stalled `go test -fuzz` to 0 execs/s and, on a memory-
// constrained CI runner, OOM-killed it -- not a message-size or connector defect
// (option.WithGRPCConn bypasses grpc-go's dial options entirely, so this harness's
// client conn keeps the real 4MB receive cap regardless of reuse). Reusing the
// fixture removes the per-iteration teardown that leaked, without changing what's
// exercised: GetSecret's OWN per-call client-create/close behavior (c.client(ctx)
// then defer cl.Close()) is still exercised every iteration -- gcpSMAccessAPI's
// Close() on the injected fake is a deliberate no-op (see reusableGCPClient below)
// precisely so that per-call Close() semantics stay real without tearing down the
// shared fixture underneath it.
//
// fakeSecretManagerServer's response fields are mutated between iterations while
// the same object may still be in use by a goroutine fuzzutil.Guard left running
// past a timeout (Guard's own documented behavior: a timed-out call's goroutine is
// never cancelled, only abandoned) -- guarded by a mutex for that reason, not
// because concurrent fuzz iterations within one worker process are expected (they
// aren't; each worker process drives its inputs one at a time).
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
// execution fast -- confirmed by reading gax-go's invoke(): its own 60s
// gax.WithTimeout override only applies "if the context doesn't already have a
// deadline" (invoke.go), so callCtx's 500ms deadline wins, and gax's retry Sleep()
// is itself ctx.Done()-aware, not a bare time.Sleep.
import (
	"context"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	gax "github.com/googleapis/gax-go/v2"
	"github.com/keyorixhq/keyorix/internal/fuzzutil"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// fakeSecretManagerServer answers every AccessSecretVersion call according to
// whatever response is currently configured via setResponse: code == 0 (OK)
// returns payload as the secret's Data; any other code returns a gRPC error with
// that code and msg. hits counts every call for the retry-bounded oracle (a).
// mu guards the response fields -- see the file-level comment for why: a call
// fuzzutil.Guard abandoned past its timeout can still be reading these when the
// next iteration reconfigures them.
type fakeSecretManagerServer struct {
	secretmanagerpb.UnimplementedSecretManagerServiceServer
	mu      sync.RWMutex
	code    codes.Code
	msg     string
	payload []byte
	name    string
	hits    int32
}

func (s *fakeSecretManagerServer) setResponse(code codes.Code, msg string, payload []byte, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.code, s.msg, s.payload, s.name = code, msg, payload, name
	atomic.StoreInt32(&s.hits, 0)
}

func (s *fakeSecretManagerServer) AccessSecretVersion(_ context.Context, _ *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	atomic.AddInt32(&s.hits, 1)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.code != codes.OK {
		return nil, status.Error(s.code, s.msg)
	}
	return &secretmanagerpb.AccessSecretVersionResponse{
		Name:    s.name,
		Payload: &secretmanagerpb.SecretPayload{Data: s.payload},
	}, nil
}

// reusableGCPClient wraps a real, shared secretmanager client and no-ops Close().
// GetSecret (gcpsm.go) calls Close() on the client it gets from c.client(ctx)
// after every single call -- correct production behavior (a fresh client really
// is created and torn down per call there), which this fake preserves exercising
// faithfully. What it must NOT do is actually tear down the shared fixture this
// fuzz target reuses across thousands of iterations; see the file-level comment.
type reusableGCPClient struct {
	cl gcpSMAccessAPI
}

func (r reusableGCPClient) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return r.cl.AccessSecretVersion(ctx, req, opts...)
}

func (r reusableGCPClient) Close() error { return nil }

func FuzzGCPSMConnectorResponse(f *testing.F) {
	f.Add(uint32(0), []byte("s3cr3t"), "projects/p/secrets/db/versions/1", "")
	f.Add(uint32(0), []byte(nil), "projects/p/secrets/db/versions/1", "")
	f.Add(uint32(5), []byte(nil), "", "not found")          // codes.NotFound
	f.Add(uint32(7), []byte(nil), "", "permission denied")  // codes.PermissionDenied
	f.Add(uint32(8), []byte(nil), "", "resource exhausted") // codes.ResourceExhausted
	f.Add(uint32(13), []byte(nil), "", "internal")          // codes.Internal

	lis := bufconn.Listen(1 << 20)
	grpcSrv := grpc.NewServer()
	fakeSrv := &fakeSecretManagerServer{}
	secretmanagerpb.RegisterSecretManagerServiceServer(grpcSrv, fakeSrv)
	go func() { _ = grpcSrv.Serve(lis) }()

	dialCtx := context.Background()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		f.Fatalf("unexpected grpc.NewClient error: %v", err)
	}

	cl, err := secretmanager.NewClient(dialCtx, option.WithGRPCConn(conn))
	if err != nil {
		f.Fatalf("unexpected secretmanager.NewClient error: %v", err)
	}

	f.Cleanup(func() {
		_ = cl.Close()
		_ = conn.Close()
		grpcSrv.Stop()
		_ = lis.Close()
	})

	c := NewGCPSecretManagerConnector("fuzz", "p", nil)
	c.newClient = func(_ context.Context) (gcpSMAccessAPI, error) { return reusableGCPClient{cl: cl}, nil }

	f.Fuzz(func(t *testing.T, rawCode uint32, payload []byte, name, msg string) {
		code := codes.Code(rawCode % 17) // codes.OK(0) .. codes.Unauthenticated(16)
		fakeSrv.setResponse(code, msg, payload, name)

		callCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		var val string
		var err error
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

		if fd := connectOpenFDCount(); fd > connectLeakCeiling {
			t.Fatalf("fd leak: %d open file descriptors after GCPSecretManagerConnector.GetSecret (expected O(10))", fd)
		}
	})
}

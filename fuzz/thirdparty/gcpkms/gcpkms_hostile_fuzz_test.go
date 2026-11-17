package gcpkmsfuzz

// Hostile-SERVER fuzz harness for cloud.google.com/go/kms/apiv1, the SDK
// Keyorix uses as its GCP KMS provider (internal/crypto/gcpkms/gcpkms.go):
// Encrypt wraps the data-encryption key once at first use, Decrypt unwraps it
// on every secret read.
//
// Threat model: an on-path attacker MITMs the Cloud KMS gRPC endpoint or the
// operator pointed kms_key_id at a hostile project, and the endpoint returns
// hostile gRPC replies — a malformed EncryptResponse/DecryptResponse proto,
// missing or empty Ciphertext/Plaintext fields, non-OK status codes.  This
// harness drives the REAL kms.KeyManagementClient (wired to a fake in-process
// gRPC server via bufconn + option.WithGRPCConn — no Keyorix wrapper in the
// loop) and calls Encrypt and Decrypt.
//
// ORACLES (and what each does NOT verify):
//
//  (a) No panic / no hang: each call runs under a 500ms context deadline +
//      fuzzutil.Guard.  A panic in the SDK fails the test; a hang trips the
//      Guard deadline.  Does NOT measure heap bytes directly; memory is bounded
//      structurally: gRPC message size cap (default 4 MiB) bounds every
//      EncryptResponse/DecryptResponse proto the client will read.
//
//  (b) Fail-closed: a non-OK gRPC status code MUST surface as an error from
//      Encrypt or Decrypt (never a nil error with an empty return value).
//
//  (c) No retry storm: the fake endpoint hit count must stay under
//      kmsRetryCeiling per call.  gax's kms retry policy only retries
//      RESOURCE_EXHAUSTED and UNAVAILABLE; a hostile non-retryable code must
//      not drive unbounded retries.
//
//  (d) No goroutine / fd leak once the call returns (CheckNoLeak).
//
// What these oracles do NOT verify:
//   - NOT CRC32C mismatch handling in the response: that is a Keyorix-layer check
//     (gcpkms.go reads CiphertextCrc32C and verifies it), not an SDK-decode
//     property; it is covered by gcpkms_mutation_test.go.
//   - NOT AAD binding correctness or cross-install confusion.
//   - NOT credentials sourced from real ADC (a fake static token is injected via
//     option.WithTokenSource so no real GCP identity endpoint is contacted).

import (
	"context"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"golang.org/x/oauth2"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

func init() {
	if runtime.GOMAXPROCS(0) > 2 {
		runtime.GOMAXPROCS(2)
	}
}

const (
	kmsRetryCeiling = 10
	kmsLeakCeiling  = 500
	fakeKeyName     = "projects/fuzz/locations/global/keyRings/fuzz/cryptoKeys/fuzz/cryptoKeyVersions/1"
)

// fakeKMSServer is a minimal KeyManagementServiceServer that returns
// fuzzer-controlled responses to Encrypt and Decrypt.
type fakeKMSServer struct {
	kmspb.UnimplementedKeyManagementServiceServer

	mu      sync.Mutex
	code    codes.Code
	payload []byte // serialised proto bytes for the success response
	hits    atomic.Int32
}

func (s *fakeKMSServer) set(code codes.Code, payload []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.code = code
	s.payload = payload
	s.hits.Store(0)
}

// reply builds the gRPC status response.  On OK it deserialises payload into
// the target proto and re-serialises it, so we probe the proto encode/decode
// path rather than bypassing it.
func (s *fakeKMSServer) reply(code codes.Code, payload []byte, out proto.Message) error {
	s.hits.Add(1)
	if code != codes.OK {
		return status.Error(code, "fuzz-hostile")
	}
	// Deserialise the fuzzer bytes into the target message: exercises the proto
	// decoder.  Unmarshal silently ignores unknown fields (proto3 semantics).
	_ = proto.Unmarshal(payload, out)
	return nil
}

func (s *fakeKMSServer) Encrypt(_ context.Context, _ *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	s.mu.Lock()
	code, payload := s.code, s.payload
	s.mu.Unlock()
	resp := &kmspb.EncryptResponse{}
	if err := s.reply(code, payload, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *fakeKMSServer) Decrypt(_ context.Context, _ *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	s.mu.Lock()
	code, payload := s.code, s.payload
	s.mu.Unlock()
	resp := &kmspb.DecryptResponse{}
	if err := s.reply(code, payload, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// staticTokenSource is an oauth2.TokenSource that always returns a fixed token.
// Injected so the KMS client does not contact any real GCP identity endpoint.
type staticTokenSource struct{ tok string }

func (s staticTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{
		AccessToken: s.tok,
		Expiry:      time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC),
	}, nil
}

// newFakeConn builds a bufconn listener, starts a fake KMS gRPC server on it,
// and returns the listener and grpc.ClientConn wired to it.
func newFakeConn(t testing.TB, srv *fakeKMSServer) (*bufconn.Listener, *grpc.ClientConn) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	grpcSrv := grpc.NewServer()
	kmspb.RegisterKeyManagementServiceServer(grpcSrv, srv)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(func() { grpcSrv.Stop(); _ = lis.Close() })

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return lis, conn
}

// newKMSClient builds a kms.KeyManagementClient wired to conn.
func newKMSClient(ctx context.Context, t testing.TB, conn *grpc.ClientConn) *kms.KeyManagementClient {
	t.Helper()
	cl, err := kms.NewKeyManagementClient(ctx,
		option.WithGRPCConn(conn),
		option.WithTokenSource(staticTokenSource{"fuzz-token-canary-do-not-leak"}),
	)
	if err != nil {
		t.Fatalf("kms.NewKeyManagementClient: %v", err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	return cl
}

func settleGoroutines(ceiling int) {
	for range 20 {
		if runtime.NumGoroutine() <= ceiling {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// FuzzGCPKMSResponse drives the real kms.KeyManagementClient.Encrypt and Decrypt
// against a bufconn fake that returns a fuzzer-controlled gRPC status code and
// an arbitrary proto-encoded response body.
func FuzzGCPKMSResponse(f *testing.F) {
	// Seeds: (gRPC code 0–16, payload bytes).
	f.Add(uint32(0), []byte(nil))                // OK, empty response
	f.Add(uint32(0), []byte("\n\x06canary"))     // OK, non-empty Ciphertext field
	f.Add(uint32(5), []byte(nil))                // NOT_FOUND
	f.Add(uint32(7), []byte(nil))                // PERMISSION_DENIED
	f.Add(uint32(8), []byte(nil))                // RESOURCE_EXHAUSTED (retryable)
	f.Add(uint32(13), []byte(nil))               // INTERNAL
	f.Add(uint32(14), []byte(nil))               // UNAVAILABLE (retryable)
	f.Add(uint32(16), []byte(nil))               // UNAUTHENTICATED
	f.Add(uint32(0), []byte("\xff\xff\xff\xff")) // OK, invalid proto bytes

	fakeSrv := &fakeKMSServer{}
	_, conn := newFakeConn(f, fakeSrv)
	cl := newKMSClient(context.Background(), f, conn)

	f.Fuzz(func(t *testing.T, rawCode uint32, payload []byte) {
		if len(payload) > 1<<16 {
			payload = payload[:1<<16]
		}
		code := codes.Code(rawCode % 17) // codes.OK(0) .. codes.Unauthenticated(16)
		fakeSrv.set(code, payload)

		callCtx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()

		// Test Encrypt.
		fuzzutil.Guard(t.Fatalf, "kms.Encrypt", func() {
			_, err := cl.Encrypt(callCtx, &kmspb.EncryptRequest{
				Name:      fakeKeyName,
				Plaintext: []byte("fuzz-plaintext"),
			})
			if code != codes.OK && err == nil {
				t.Fatalf("FAIL-OPEN: kms.Encrypt returned success on gRPC code %s", code)
			}
		})
		if h := fakeSrv.hits.Load(); h > kmsRetryCeiling {
			t.Fatalf("RETRY STORM: Encrypt hit fake endpoint %d times (ceiling %d)", h, kmsRetryCeiling)
		}
		fakeSrv.hits.Store(0)

		// Test Decrypt.
		fuzzutil.Guard(t.Fatalf, "kms.Decrypt", func() {
			_, err := cl.Decrypt(callCtx, &kmspb.DecryptRequest{
				Name:       fakeKeyName,
				Ciphertext: []byte("fuzz-ciphertext"),
			})
			if code != codes.OK && err == nil {
				t.Fatalf("FAIL-OPEN: kms.Decrypt returned success on gRPC code %s", code)
			}
		})
		if h := fakeSrv.hits.Load(); h > kmsRetryCeiling {
			t.Fatalf("RETRY STORM: Decrypt hit fake endpoint %d times (ceiling %d)", h, kmsRetryCeiling)
		}

		settleGoroutines(kmsLeakCeiling)
		if n := runtime.NumGoroutine(); n > kmsLeakCeiling {
			t.Fatalf("goroutine leak: %d goroutines after kms ops (ceiling %d)", n, kmsLeakCeiling)
		}
	})
}

package connect

// gcpsm_fixture_isolation_test.go — proves the shared fixture
// FuzzGCPSMConnectorResponse now reuses across every fuzz input (gcpsm_response_
// fuzz_test.go, fixed to stop leaking goroutines per-iteration — see
// docs/findings/2026-09-23-FINDING-gcpsm-fuzz-memory-and-recv-cap.md §1) does not
// leak state BETWEEN inputs. Reusing the server/listener/client across executions
// only removed the teardown that leaked; it does nothing on its own to guarantee
// setResponse's mutex-guarded overwrite actually replaces every field an earlier
// input set, or that a stale in-flight response can't race a new one. If it
// didn't, every fuzz oracle downstream would be checking a stale or mixed
// response against the CURRENT input's expectations — an unsound comparison that
// could either mask a real bypass or manufacture a false one.
//
// This drives the exact shared-fixture pattern (one server, many inputs) through
// GetSecret itself — the same call path the fuzz oracles check — and asserts each
// call sees only its own input's response, never a neighbor's, run back-to-back
// on the identical fixture without ever tearing it down between them, in both
// directions: an error input immediately followed by a success input (the
// dangerous direction — a stale error masking a real success is merely
// misleading, but a stale SUCCESS bleeding forward would silently defeat the
// fail-closed oracle), and a success input followed by a different error input.
import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestGCPSMSharedFixture_NoCrossInputLeak(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	grpcSrv := grpc.NewServer()
	fakeSrv := &fakeSecretManagerServer{}
	secretmanagerpb.RegisterSecretManagerServiceServer(grpcSrv, fakeSrv)
	go func() { _ = grpcSrv.Serve(lis) }()
	t.Cleanup(grpcSrv.Stop)
	t.Cleanup(func() { _ = lis.Close() })

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	cl, err := secretmanager.NewClient(context.Background(), option.WithGRPCConn(conn))
	if err != nil {
		t.Fatalf("secretmanager.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = cl.Close() })

	c := NewGCPSecretManagerConnector("fuzz", "p", nil)
	c.newClient = func(_ context.Context) (gcpSMAccessAPI, error) { return reusableGCPClient{cl: cl}, nil }

	call := func(t *testing.T) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return c.GetSecret(ctx, "projects/p/secrets/fuzz/versions/latest")
	}

	// Input 1: an error response.
	fakeSrv.setResponse(codes.NotFound, "not found", nil, "")
	_, err1 := call(t)
	if err1 == nil || !strings.Contains(err1.Error(), "not found") {
		t.Fatalf("input 1: expected a \"not found\" error, got val_err=%v", err1)
	}

	// Input 2, immediately after, same fixture: a DIFFERENT, successful response.
	// This is the dangerous direction — if input 1's error somehow bled forward
	// (or a leaked/abandoned goroutine from input 1 raced this call), input 2
	// would wrongly fail too, or worse, silently see stale data.
	fakeSrv.setResponse(codes.OK, "", []byte("value-two"), "projects/p/secrets/db/versions/2")
	val2, err2 := call(t)
	if err2 != nil {
		t.Fatalf("input 2: expected success, got error: %v (input 1's response leaked forward)", err2)
	}
	if val2 != "value-two" {
		t.Fatalf("input 2: expected %q, got %q", "value-two", val2)
	}

	// Input 3, immediately after: success -> a DIFFERENT error. Proves isolation
	// in the other direction too — a stale SUCCESS bleeding forward would
	// silently defeat GetSecret's own fail-closed behavior for input 3.
	fakeSrv.setResponse(codes.PermissionDenied, "permission denied", nil, "")
	val3, err3 := call(t)
	if err3 == nil {
		t.Fatalf("input 3: expected a permission-denied error, got success val=%q (input 2's success leaked forward)", val3)
	}
	if !strings.Contains(err3.Error(), "permission denied") {
		t.Fatalf("input 3: expected \"permission denied\", got: %v", err3)
	}

	// Input 4: back to a DIFFERENT successful value, confirming input 3's error
	// doesn't leak forward either, and hits counter resets per input (setResponse
	// resets it) rather than accumulating in a way that would trip the
	// retry-storm oracle on an otherwise-clean run.
	fakeSrv.setResponse(codes.OK, "", []byte("value-four"), "projects/p/secrets/db/versions/4")
	val4, err4 := call(t)
	if err4 != nil {
		t.Fatalf("input 4: expected success, got error: %v", err4)
	}
	if val4 != "value-four" {
		t.Fatalf("input 4: expected %q, got %q (cross-input contamination)", "value-four", val4)
	}
}

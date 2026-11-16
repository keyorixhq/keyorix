package interceptors

// Red/green proof that the GE1 edge oracle (edgeViolation) is not vacuous: each
// planted defect makes the SAME predicate the fuzzer uses fire, and the benign
// shape passes. "A guard nobody has watched fail is not a guard." No production
// code is modified — the defects are injected into test-only chains/observations.

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func edgeNoBudget() resguard.Budget {
	return resguard.Budget{Target: "rg", Factor: 8, Meters: map[string]resguard.MeterBudget{}}
}

// (1) No-panic oracle.
func TestGE1Oracle_NoPanic_RedGreen(t *testing.T) {
	green := edgeObservation{reached: true, reachedUC: &UserContext{UserID: 1}}
	if v := edgeViolation(green, edgeNoBudget()); v != "" {
		t.Fatalf("GREEN should pass, got %q", v)
	}
	red := edgeObservation{sawPanic: true, reached: false, err: status.Error(codes.Internal, "x")}
	if v := edgeViolation(red, edgeNoBudget()); v == "" {
		t.Fatal("RED: a caught panic must fire the no-panic oracle")
	}
}

// (2) Fail-closed oracle — three distinct violation shapes.
func TestGE1Oracle_FailClosed_RedGreen(t *testing.T) {
	b := edgeNoBudget()
	// GREEN A: reached with a real principal.
	if v := edgeViolation(edgeObservation{reached: true, reachedUC: &UserContext{UserID: 1}}, b); v != "" {
		t.Fatalf("GREEN reached+auth should pass, got %q", v)
	}
	// GREEN B: not reached, fail-closed with a proper status.
	if v := edgeViolation(edgeObservation{reached: false, err: status.Error(codes.Unauthenticated, "no")}, b); v != "" {
		t.Fatalf("GREEN fail-closed should pass, got %q", v)
	}
	// RED 1: handler reached WITHOUT an authenticated UserContext.
	if v := edgeViolation(edgeObservation{reached: true, reachedUC: nil}, b); v == "" {
		t.Fatal("RED: unauthenticated reach must fire")
	}
	// RED 2: handler reached but chain also returned an error (partial eval).
	if v := edgeViolation(edgeObservation{reached: true, reachedUC: &UserContext{UserID: 1}, err: errors.New("boom")}, b); v == "" {
		t.Fatal("RED: reached-with-error must fire")
	}
	// RED 3: chain returned OK but the handler never ran.
	if v := edgeViolation(edgeObservation{reached: false, err: nil}, b); v == "" {
		t.Fatal("RED: OK-without-handler must fire")
	}
}

// (5) Status discipline.
func TestGE1Oracle_StatusDiscipline_RedGreen(t *testing.T) {
	b := edgeNoBudget()
	if v := edgeViolation(edgeObservation{reached: false, err: status.Error(codes.PermissionDenied, "x")}, b); v != "" {
		t.Fatalf("GREEN permitted code should pass, got %q", v)
	}
	// RED: a raw non-status error.
	if v := edgeViolation(edgeObservation{reached: false, err: errors.New("plain")}, b); v == "" {
		t.Fatal("RED: non-status error must fire")
	}
	// RED: a status code outside the fail-closed set (e.g. NotFound).
	if v := edgeViolation(edgeObservation{reached: false, err: status.Error(codes.NotFound, "x")}, b); v == "" {
		t.Fatal("RED: unexpected status code must fire")
	}
}

// (4) Leak oracle — error channel and log channel.
func TestGE1Oracle_Leak_RedGreen(t *testing.T) {
	b := edgeNoBudget()
	secret := "ge1topsecret"
	if v := edgeViolation(edgeObservation{reached: false, err: status.Error(codes.Unauthenticated, "invalid token"), serverSecrets: []string{secret}}, b); v != "" {
		t.Fatalf("GREEN clean error should pass, got %q", v)
	}
	// RED: a status message containing a server secret.
	if v := edgeViolation(edgeObservation{reached: false, err: status.Error(codes.Unauthenticated, "bad creds "+secret), serverSecrets: []string{secret}}, b); v == "" {
		t.Fatal("RED: secret in error message must fire")
	}
	// RED: echoing the supplied bearer token back in the error.
	tok := "kx_pat_supplied_abcdef"
	if v := edgeViolation(edgeObservation{reached: false, err: status.Error(codes.Unauthenticated, "rejected "+tok), suppliedTok: tok}, b); v == "" {
		t.Fatal("RED: bearer-token echo must fire")
	}
	// RED: secret in the log channel.
	if v := edgeViolation(edgeObservation{reached: true, reachedUC: &UserContext{UserID: 1}, leakedLog: []string{secret}}, b); v == "" {
		t.Fatal("RED: secret in logs must fire")
	}
}

// (3) Bounded-work oracle.
func TestGE1Oracle_Bounded_RedGreen(t *testing.T) {
	budget := resguard.Budget{Target: "rg", Factor: 4, Meters: map[string]resguard.MeterBudget{
		"alloc_bytes": {Floor: 1024, PerByte: 10},
	}}
	green := edgeObservation{reached: true, reachedUC: &UserContext{UserID: 1}, cost: resguard.Cost{InputLen: 100, Sampled: true, AllocBytes: 2000}}
	if v := edgeViolation(green, budget); v != "" {
		t.Fatalf("GREEN bounded alloc should pass, got %q", v)
	}
	red := edgeObservation{reached: true, reachedUC: &UserContext{UserID: 1}, cost: resguard.Cost{InputLen: 100, Sampled: true, AllocBytes: 50 << 20}}
	if v := edgeViolation(red, budget); v == "" {
		t.Fatal("RED: super-linear alloc must fire the bounded-work oracle")
	}
}

// End-to-end RED through the real chain composer: a chain that OMITS
// AuthInterceptor lets a hostile token reach the handler with no principal —
// exactly the partial-evaluation defect oracle (2) exists to catch. Proven here
// directly (not just on a synthesized observation) so the oracle is validated
// against the real chainUnary wiring, not only against hand-built structs.
func TestGE1Oracle_ChainWithoutAuth_ReachesHandlerUnauthenticated(t *testing.T) {
	info := &grpc.UnaryServerInfo{FullMethod: "/keyorix.v1.SecretService/GetSecret"}
	var reached bool
	var uc *UserContext
	handler := func(ctx context.Context, _ any) (any, error) {
		reached = true
		uc = GetUserFromGRPCContext(ctx)
		return "ok", nil
	}
	// Defect: Recovery + Timeout but NO AuthInterceptor.
	broken := chainUnary(RecoveryInterceptor(), TimeoutInterceptor(0))
	_, err := broken(context.Background(), nil, info, handler)
	obs := edgeObservation{reached: reached, reachedUC: uc, err: err}
	if v := edgeViolation(obs, edgeNoBudget()); v == "" {
		t.Fatal("RED: auth-less chain reaching the handler must fire the fail-closed oracle")
	}
}

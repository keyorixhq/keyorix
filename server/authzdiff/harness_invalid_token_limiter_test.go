package authzdiff

import (
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
)

// Fuzz-corpus issue #118: FuzzAuthzDiff reported
//
//	UNEXPLAINED userrole.assign principal=suspended target=B arg=2 ...
//	grpc=other(ResourceExhausted) => mapping-gap:other-where-model-denies:grpc
//
// as a product defect. It is a harness artefact: the per-IP invalid-token
// brute-force limiter (PAT-003) is a process-global in-memory bucket, NOT part
// of the per-iteration fresh store, and the harness drives every leg from one
// constant bufconn peer. A suspended principal's rejected token spends that
// shared budget, so a later case's gRPC probe comes back ResourceExhausted. The
// REST leg (HTTP 429) and the sequence driver already excuse that as n/a;
// runLayer's REST/gRPC legs did not, so the gRPC leg mapped it to Other and
// classify() raised a mapping-gap. The fix excuses the invalid-token limiter on
// both transports in runLayer.

func specByName(t *testing.T, name string) opSpec {
	t.Helper()
	for _, s := range withDerived(t, ops()) {
		if s.name == name {
			return s
		}
	}
	t.Fatalf("op %q not found in ops()", name)
	return opSpec{}
}

// drainGRPCInvalidTokenLimiter drives the process-global per-IP invalid-token
// limiter to exhaustion over one reused gRPC leg, using the suspended
// principal's validated-then-rejected token (each probe spends one unit of the
// shared budget), and returns the limiter's ResourceExhausted error. It loops
// generously because the bucket refills at 1/s while draining.
func drainGRPCInvalidTokenLimiter(t *testing.T, spec opSpec, susp *principal) error {
	t.Helper()
	lg := newLeg(t, layerGRPC)
	defer lg.close()
	var last error
	for range 60 {
		err := spec.grpc(grpcCtx(susp), lg, tB, 2)
		if grpcInvalidTokenLimited(err) {
			return err
		}
		last = err
	}
	t.Fatalf("could not drive the gRPC invalid-token limiter to ResourceExhausted; last probe err = %v", last)
	return nil
}

// TestGRPCInvalidTokenLimiter_DiscriminatesOtherResourceExhausted is the
// deterministic, timing-free core of the #118 fix: the limiter refusal is
// recognised (→ n/a) while every OTHER codes.ResourceExhausted producer is NOT
// absorbed and still maps to Other via grpcOutcome. Red without the fix:
// grpcInvalidTokenLimited does not exist, so runLayer cannot tell the limiter
// apart from a secret-too-large refusal and both the limiter leak and this
// discrimination are untested.
func TestGRPCInvalidTokenLimiter_DiscriminatesOtherResourceExhausted(t *testing.T) {
	limiter := status.Error(codes.ResourceExhausted, grpcInvalidTokenLimiterMsg)
	if !grpcInvalidTokenLimited(limiter) {
		t.Fatal("the invalid-token limiter refusal must be recognised so runLayer records it n/a")
	}
	// Sanity: the generic mapping still calls it Other — that is exactly why
	// runLayer has to special-case it rather than rely on grpcOutcome.
	if got := grpcOutcome(limiter).Outcome; got != Other {
		t.Fatalf("grpcOutcome should still map the limiter refusal to Other, got %v", got)
	}

	// The three other ResourceExhausted producers must stay Other, never n/a:
	// oversized secret value, the audit-stream cap, and the per-principal rate
	// limiter. If grpcInvalidTokenLimited absorbed any of them it would hide a
	// genuine harness-health or disagreement signal.
	tooLarge := &core.SecretValueTooLargeError{Size: 200, Limit: 100}
	others := []error{
		status.Error(codes.ResourceExhausted, tooLarge.Error()),                                                    // secret_service.go
		status.Errorf(codes.ResourceExhausted, "too many concurrent audit streams for this principal (max %d)", 3), // audit_service.go
		status.Error(codes.ResourceExhausted, "too many requests; slow down"),                                      // per-principal rate_limit.go
	}
	for _, e := range others {
		if grpcInvalidTokenLimited(e) {
			t.Errorf("a non-limiter ResourceExhausted was wrongly absorbed as the invalid-token limiter: %v", e)
		}
		if got := grpcOutcome(e).Outcome; got != Other {
			t.Errorf("a non-limiter ResourceExhausted must still map to Other, got %v for %v", got, e)
		}
	}
	if grpcInvalidTokenLimited(nil) {
		t.Error("a nil error must never be read as the limiter")
	}
}

// TestRunLayer_InvalidTokenLimiterLeak_RecordedNA_Not_MappingGap reproduces #118
// against the real gRPC server: it drains the shared limiter with a suspended
// token, shows that the pre-fix gRPC mapping would have raised the reported
// mapping-gap, and asserts the fixed runLayer records the gRPC leg as n/a.
func TestRunLayer_InvalidTokenLimiterLeak_RecordedNA_Not_MappingGap(t *testing.T) {
	spec := specByName(t, "userrole.assign")
	_, fx := template(t)
	susp := fx.principals[pkSuspended]
	k := caseKey{Op: spec.name, Principal: pkSuspended, Target: tB.String(), Arg: 2, variation: defaultVariation}

	// The limiter bucket is process-global (burst 10, refill 1/s) and this test
	// leaves it empty; later tests (TestSeqControl) count a limited probe as a
	// failure. There is no test reset hook on the gRPC side, so wait out a full
	// refill before returning.
	t.Cleanup(func() { time.Sleep(11 * time.Second) })

	// (a) Pre-fix behaviour, demonstrated directly rather than by reverting
	// production code: grpcOutcome is exactly the mapping the old runLayer gRPC
	// leg used. The leaked limiter refusal maps to Other, and a suspended
	// (model=Denied) case with that leg classifies as the #118 mapping-gap.
	limitErr := drainGRPCInvalidTokenLimiter(t, spec, susp)
	if got := grpcOutcome(limitErr).Outcome; got != Other {
		t.Fatalf("precondition: the pre-fix gRPC mapping of the limiter refusal must be Other, got %v", got)
	}
	preFix := &caseResult{
		caseKey: k,
		Model:   Denied,
		Legs:    map[layer]*legOutcome{layerGRPC: {Outcome: Other, Detail: codes.ResourceExhausted.String()}},
	}
	if cs := classify(spec, susp, preFix); !slices.Contains(cs, "mapping-gap:other-where-model-denies:grpc") {
		t.Fatalf("expected the historical #118 mapping-gap from the pre-fix mapping, got %v", cs)
	}

	// (b) Post-fix behaviour: runLayer's gRPC leg excuses the same leaked refusal
	// as n/a, so it reaches neither oracle. Retried because the shared bucket
	// refills at 1/s — re-drain if a probe slips through before runLayer runs.
	var got *legOutcome
	for range 6 {
		_ = drainGRPCInvalidTokenLimiter(t, spec, susp)
		got = runLayer(t, spec, layerGRPC, susp, k, tB, nil)
		if got.NA == "invalid-token rate limiter" {
			break
		}
	}
	if got.NA != "invalid-token rate limiter" {
		t.Fatalf("with the fix the gRPC leg must be n/a (invalid-token rate limiter); got NA=%q outcome=%q detail=%q",
			got.NA, got.Outcome, got.Detail)
	}
}

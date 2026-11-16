package httpx_test

// Red/green proof that the GE1 httpx-decode oracle (decodeEdgeViolation) is not
// vacuous: each planted defect fires the same predicate the fuzzer uses, and the
// benign shape passes. No production code is modified.

import (
	"net/http"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

func decodeNoBudget() resguard.Budget {
	return resguard.Budget{Target: "rg", Factor: 10, Meters: map[string]resguard.MeterBudget{}}
}

func TestGE1XOracle_StatusDiscipline_RedGreen(t *testing.T) {
	b := decodeNoBudget()
	if v := decodeEdgeViolation(decodeObservation{status: http.StatusBadRequest, reached: false, okDecode: false}, b); v != "" {
		t.Fatalf("GREEN 400 should pass, got %q", v)
	}
	// RED: a status outside {200,400,413}.
	if v := decodeEdgeViolation(decodeObservation{status: http.StatusInternalServerError, reached: false, okDecode: false}, b); v == "" {
		t.Fatal("RED: unexpected status must fire")
	}
}

func TestGE1XOracle_FailClosed_RedGreen(t *testing.T) {
	b := decodeNoBudget()
	// GREEN: success → reached.
	if v := decodeEdgeViolation(decodeObservation{status: 200, reached: true, okDecode: true}, b); v != "" {
		t.Fatalf("GREEN success should pass, got %q", v)
	}
	// GREEN: failure → not reached.
	if v := decodeEdgeViolation(decodeObservation{status: 400, reached: false, okDecode: false}, b); v != "" {
		t.Fatalf("GREEN fail-closed should pass, got %q", v)
	}
	// RED: handler reached despite a failed decode (garbage/partial reach).
	if v := decodeEdgeViolation(decodeObservation{status: 200, reached: true, okDecode: false}, b); v == "" {
		t.Fatal("RED: reached-with-failed-decode must fire")
	}
	// RED: decode failed yet response was 200.
	if v := decodeEdgeViolation(decodeObservation{status: 200, reached: false, okDecode: false}, b); v == "" {
		t.Fatal("RED: failed-decode-with-200 must fire")
	}
}

func TestGE1XOracle_Leak_RedGreen(t *testing.T) {
	b := decodeNoBudget()
	if v := decodeEdgeViolation(decodeObservation{status: 400, reached: false, okDecode: false, respBody: `{"error":"InvalidJSON"}`}, b); v != "" {
		t.Fatalf("GREEN clean error should pass, got %q", v)
	}
	// RED: response echoes the body canary.
	if v := decodeEdgeViolation(decodeObservation{status: 400, reached: false, okDecode: false, respBody: "bad body: " + edgeBodyCanary}, b); v == "" {
		t.Fatal("RED: body-canary echo must fire")
	}
}

func TestGE1XOracle_Bounded_RedGreen(t *testing.T) {
	budget := resguard.Budget{Target: "rg", Factor: 4, Meters: map[string]resguard.MeterBudget{
		"alloc_bytes": {Floor: 4096, PerByte: 20},
	}}
	green := decodeObservation{status: 200, reached: true, okDecode: true, cost: resguard.Cost{InputLen: 100, Sampled: true, AllocBytes: 8000}}
	if v := decodeEdgeViolation(green, budget); v != "" {
		t.Fatalf("GREEN bounded should pass, got %q", v)
	}
	red := decodeObservation{status: 200, reached: true, okDecode: true, cost: resguard.Cost{InputLen: 100, Sampled: true, AllocBytes: 80 << 20}}
	if v := decodeEdgeViolation(red, budget); v == "" {
		t.Fatal("RED: super-linear alloc must fire the bounded-work oracle")
	}
}

// End-to-end GREEN through the real middleware + MustDecodeBody: a benign JSON
// body decodes and reaches the handler; a malformed one 400s and does not.
func TestGE1XOracle_RealPath_GreenBothOutcomes(t *testing.T) {
	ok := runDecodeInput(1, "application/json", []byte(`{"name":"x","count":3}`))
	if v := decodeEdgeViolation(ok, decodeNoBudget()); v != "" || !ok.reached || ok.status != 200 {
		t.Fatalf("GREEN benign decode: v=%q reached=%v status=%d", v, ok.reached, ok.status)
	}
	bad := runDecodeInput(1, "application/json", []byte(`{not json`))
	if v := decodeEdgeViolation(bad, decodeNoBudget()); v != "" || bad.reached || bad.status != 400 {
		t.Fatalf("GREEN malformed decode: v=%q reached=%v status=%d", v, bad.reached, bad.status)
	}
}

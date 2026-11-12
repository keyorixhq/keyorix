package wirefuzz

// oracle_redproof_test.go is the standing RED/GREEN proof for the wire-fuzz oracles.
// Per the repo rule "a guard nobody has watched fail is not a guard", each oracle is
// exercised in BOTH directions: a planted defect must make evalHTTP1Oracles fire
// (red), and a clean input must leave it silent (green). TestRedProof_EndToEnd_Leak
// goes further and drives a DELIBERATELY BROKEN listener through the SAME
// exchange + recorder + oracle pipeline the fuzzer uses, proving the wiring — not
// just the predicate — catches a planted leak, while the real stack stays green.
//
// This file is committed on purpose (it is not a throwaway plant): it is the
// evidence that the fuzzer's oracles are load-bearing.

import (
	"bytes"
	"net"
	"net/http"
	"testing"
	"time"
)

// --- Per-oracle predicate red/green (fast, no network) ---------------------------

func TestRedProof_Oracle_SmugglingCount(t *testing.T) {
	gs := genStream{topLevel: 1}
	// RED: two handler invocations for one top-level request.
	if v := evalHTTP1Oracles(gs, nil, []handlerHit{{path: "/a"}, {path: "/b"}}, 0, "A", "B"); v == "" {
		t.Fatal("smuggling-count oracle did not fire on 2 hits for 1 top-level request")
	}
	// GREEN: one hit for one request.
	if v := evalHTTP1Oracles(gs, nil, []handlerHit{{path: "/a"}}, 0, "A", "B"); v != "" {
		t.Fatalf("smuggling-count oracle false-positived on a clean exchange: %s", v)
	}
}

func TestRedProof_Oracle_Canary(t *testing.T) {
	gs := genStream{topLevel: 3} // high enough that the count oracle stays silent
	// RED: a body-embedded canary request was dispatched.
	if v := evalHTTP1Oracles(gs, nil, []handlerHit{{path: canaryPath}}, 0, "A", "B"); v == "" {
		t.Fatal("canary oracle did not fire on a dispatched canary path")
	}
	// GREEN: ordinary paths only.
	if v := evalHTTP1Oracles(gs, nil, []handlerHit{{path: "/api/v1/secrets/value"}}, 0, "A", "B"); v != "" {
		t.Fatalf("canary oracle false-positived: %s", v)
	}
}

func TestRedProof_Oracle_LeakWithoutCredential(t *testing.T) {
	const valA, valB = "VALUE-A-9f3c1", "VALUE-B-6b28e"
	respB := []byte("HTTP/1.1 200 OK\r\n\r\n{\"value\":\"" + valB + "\"}")
	// RED: secret B leaked with no admin credential.
	if v := evalHTTP1Oracles(genStream{topLevel: 1, hasAdmin: false}, respB, nil, 0, valA, valB); v == "" {
		t.Fatal("leak oracle did not fire on secret B without admin credential")
	}
	// GREEN: same body, but admin credential was on the wire (authorized read).
	if v := evalHTTP1Oracles(genStream{topLevel: 1, hasAdmin: true}, respB, nil, 0, valA, valB); v != "" {
		t.Fatalf("leak oracle false-positived on an authorized read: %s", v)
	}
	// RED: secret A leaked with neither admin nor reader on the wire.
	respA := []byte("HTTP/1.1 200 OK\r\n\r\n{\"value\":\"" + valA + "\"}")
	if v := evalHTTP1Oracles(genStream{topLevel: 1}, respA, nil, 0, valA, valB); v == "" {
		t.Fatal("leak oracle did not fire on secret A without any credential")
	}
	// GREEN: secret A with the scoped reader credential present.
	if v := evalHTTP1Oracles(genStream{topLevel: 1, hasReader: true}, respA, nil, 0, valA, valB); v != "" {
		t.Fatalf("leak oracle false-positived on an authorized reader read: %s", v)
	}
}

func TestRedProof_Oracle_ResponseSplitting(t *testing.T) {
	// RED: an injected header materialized in the first response header block.
	split := []byte("HTTP/1.1 200 OK\r\nX-Injected: 1\r\n\r\nbody")
	if v := evalHTTP1Oracles(genStream{topLevel: 1, injects: true}, split, nil, 0, "A", "B"); v == "" {
		t.Fatal("splitting oracle did not fire on an injected response header")
	}
	// GREEN: same bytes, but no injection payload was emitted this input.
	if v := evalHTTP1Oracles(genStream{topLevel: 1, injects: false}, split, nil, 0, "A", "B"); v != "" {
		t.Fatalf("splitting oracle false-positived when no injection was emitted: %s", v)
	}
	// RED: two 2xx responses for one top-level request.
	two := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	if v := evalHTTP1Oracles(genStream{topLevel: 1, injects: true}, two, nil, 0, "A", "B"); v == "" {
		t.Fatal("splitting oracle did not fire on 2 x 2xx for 1 request")
	}
}

func TestRedProof_Oracle_UnboundedAlloc(t *testing.T) {
	// RED: alloc delta over the cap.
	if v := evalHTTP1Oracles(genStream{topLevel: 1}, nil, nil, http1AllocCap+1, "A", "B"); v == "" {
		t.Fatal("alloc oracle did not fire above the cap")
	}
	// GREEN: alloc delta under the cap.
	if v := evalHTTP1Oracles(genStream{topLevel: 1}, nil, nil, http1AllocCap-1, "A", "B"); v != "" {
		t.Fatalf("alloc oracle false-positived under the cap: %s", v)
	}
}

// --- End-to-end: a planted-leak listener through the real pipeline ---------------

// TestRedProof_EndToEnd_Leak stands up a broken listener whose handler returns secret
// A's plaintext for ANY request, with no authentication — the exact confused-deputy
// defect the leak oracle exists to catch — and drives it through the real
// exchange() + recorder + evalHTTP1Oracles path. The oracle must fire. It then
// confirms the SAME pipeline is green against the real seeded stack with an
// unauthenticated request.
func TestRedProof_EndToEnd_Leak(t *testing.T) {
	const valA = "VALUE-A-9f3c1"

	// Broken stack: leaks valA to everyone.
	rec := &recorder{resolve: func(string) string { return "" }}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	leaky := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":"` + valA + `"}`))
	})
	srv := &http.Server{Handler: rec.wrap(leaky), ReadHeaderTimeout: wireReadHeaderTimeout}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	wire := []byte("GET /api/v1/secrets/value?ref=proja/prod/sa HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
	resp, timedOut := exchange(ln.Addr().String(), wire, 5*time.Second)
	if timedOut {
		t.Fatal("broken stack timed out")
	}
	if !bytes.Contains(resp, []byte(valA)) {
		t.Fatalf("precondition failed: broken stack did not actually return the plaintext; resp=%q", truncate(resp, 400))
	}
	gs := genStream{wire: wire, topLevel: 1} // no credential on the wire
	if v := evalHTTP1Oracles(gs, resp, rec.snapshot(), 0, valA, "VALUE-B-6b28e"); v == "" {
		t.Fatal("RED FAILED: leak oracle did not fire against a listener that leaks the plaintext unauthenticated")
	}

	// GREEN control: the real stack, same unauthenticated request, must be clean.
	w := buildWireWorld(t)
	w.rec.reset()
	resp2, timedOut2 := exchange(w.addr, wire, 5*time.Second)
	if timedOut2 {
		t.Fatal("real stack timed out")
	}
	gs2 := generateHTTP1(w, nil) // credentials: none
	gs2.wire, gs2.topLevel = wire, 1
	if v := evalHTTP1Oracles(gs2, resp2, w.rec.snapshot(), 0, w.valA, w.valB); v != "" {
		t.Fatalf("GREEN FAILED: oracle fired against the real stack for an unauthenticated /secrets read: %s\nresp=%q", v, truncate(resp2, 400))
	}
}

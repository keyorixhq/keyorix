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

	"golang.org/x/net/http2"
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

// --- Post-abuse health probes red/green ------------------------------------------

// TestRedProof_HTTPHealthProbe watches httpHealthProbe return nil against a live
// HTTP/1.1 listener (GREEN) and a non-nil error once that listener is closed (RED) —
// the "server stopped serving a later clean request" condition the probe exists to
// detect. A minimal 200-returning handler stands in for the real router: the probe
// asserts the listener SERVES a response, not what the body says.
func TestRedProof_HTTPHealthProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
		ReadHeaderTimeout: wireReadHeaderTimeout,
	}
	go func() { _ = srv.Serve(ln) }()
	addr := ln.Addr().String()

	// GREEN: live listener serves /health.
	if err := httpHealthProbe(addr); err != nil {
		t.Fatalf("GREEN FAILED: probe errored against a live listener: %v", err)
	}
	// RED: once the server is closed, a fresh connection is refused.
	if err := srv.Close(); err != nil {
		t.Fatalf("close server: %v", err)
	}
	if err := httpHealthProbe(addr); err == nil {
		t.Fatal("RED FAILED: health probe passed against a closed listener")
	}
}

// TestRedProof_GRPCHealthProbe watches grpcHealthProbe return nil against a live
// HTTP/2 listener that emits its SETTINGS frame (GREEN) and a non-nil error once the
// listener is closed (RED). A bare x/net/http2 server stands in for grpc-go: both send
// the server SETTINGS frame on connect, which is the exact liveness signal the probe
// reads.
func TestRedProof_GRPCHealthProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	h2s := &http2.Server{} //nolint:staticcheck // SA1019: a bare framer-level h2 server is the point; http.Server would hide the SETTINGS frame the probe reads
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go h2s.ServeConn(c, &http2.ServeConnOpts{ //nolint:staticcheck // SA1019: see above
				Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }),
			})
		}
	}()
	addr := ln.Addr().String()

	// GREEN: live HTTP/2 listener sends its SETTINGS frame.
	if err := grpcHealthProbe(addr); err != nil {
		t.Fatalf("GREEN FAILED: gRPC probe errored against a live HTTP/2 listener: %v", err)
	}
	// RED: closed listener refuses a fresh connection.
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	<-done
	if err := grpcHealthProbe(addr); err == nil {
		t.Fatal("RED FAILED: gRPC health probe passed against a closed listener")
	}
}

// --- TLS + ALPN HTTP/2-on-the-HTTP-listener reachability -------------------------

// TestRedProof_TLSALPNReachability proves the FuzzWireHTTP2TLS target is NOT vacuous:
// the TLS listener actually negotiates ALPN "h2" (GREEN), and a well-formed HTTP/2
// request to /health over that connection reaches net/http's HTTP/2 server and returns
// a real response (a server SETTINGS frame + a HEADERS response for the stream). It
// also asserts the vacuity guard fires: an h2-less client (ALPN "http/1.1" only) does
// NOT negotiate h2, which the driver would flag.
func TestRedProof_TLSALPNReachability(t *testing.T) {
	w := buildTLSWireWorld(t)

	// GREEN: an h2 client negotiates h2 and the probe (SETTINGS round-trip) succeeds.
	conn, proto, err := tlsH2Dial(w.addr, w.clientCfg)
	if err != nil {
		t.Fatalf("GREEN FAILED: TLS dial: %v", err)
	}
	_ = conn.Close()
	if proto != "h2" {
		t.Fatalf("GREEN FAILED: ALPN negotiated %q, expected h2 — HTTP/2-on-the-HTTP-listener is NOT reached", proto)
	}
	if err := tlsH2HealthProbe(w.addr, w.clientCfg); err != nil {
		t.Fatalf("GREEN FAILED: h2 health probe over TLS errored: %v", err)
	}

	// The vacuity guard: a client that offers only http/1.1 must NOT get h2. If it did,
	// the driver's proto!="h2" check would be meaningless.
	h1Cfg := w.clientCfg.Clone()
	h1Cfg.NextProtos = []string{"http/1.1"}
	conn2, proto2, err := tlsH2Dial(w.addr, h1Cfg)
	if err != nil {
		t.Fatalf("http/1.1 dial: %v", err)
	}
	_ = conn2.Close()
	if proto2 == "h2" {
		t.Fatal("vacuity guard FAILED: server negotiated h2 for an http/1.1-only client")
	}
}

// TestRedProof_TLSHealthProbe watches tlsH2HealthProbe return nil against the live TLS
// listener (GREEN) and a non-nil error once it is closed (RED).
func TestRedProof_TLSHealthProbe(t *testing.T) {
	w := buildTLSWireWorld(t)
	if err := tlsH2HealthProbe(w.addr, w.clientCfg); err != nil {
		t.Fatalf("GREEN FAILED: TLS health probe errored against a live listener: %v", err)
	}
	// RED: a closed listener (dial to a now-dead port) must error. We cannot reach the
	// cleanup's srv.Close() early without the handle, so dial a definitely-closed port
	// on loopback by grabbing and releasing one.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close() // port now refuses connections
	if err := tlsH2HealthProbe(deadAddr, w.clientCfg); err == nil {
		t.Fatal("RED FAILED: TLS health probe passed against a closed port")
	}
}

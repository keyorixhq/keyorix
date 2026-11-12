package wirefuzz

// oracle_redproof_test.go is the standing RED/GREEN proof for the wire-fuzz oracles.
// Per the repo rule "a guard nobody has watched fail is not a guard", each oracle is
// exercised in BOTH directions: a planted defect must make the evaluator fire (red),
// and a clean input must leave it silent (green). The EndToEnd and *_PlantedLeak tests
// go further and drive a DELIBERATELY BROKEN server through the SAME driver +
// recorder + oracle pipeline the fuzzers use, proving the wiring — not just the
// predicate — catches a planted leak. anti_vacuity_test.go proves the converse: the
// real stack's drivers reach an authorized read at all.
//
// This file is committed on purpose (it is not a throwaway plant): it is the
// evidence that the fuzzer's oracles are load-bearing.

import (
	"bytes"
	"context"
	"maps"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	testValA = "VALUE-A-9f3c1"
	testValB = "VALUE-B-6b28e"
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
	// The raw lane skips the count (a short CL legitimately yields a second request).
	if v := evalHTTP1Oracles(genStream{topLevel: 1, raw: true}, nil, []handlerHit{{path: "/a"}, {path: "/b"}}, 0, "A", "B"); v != "" {
		t.Fatalf("count oracle must be off on the raw lane: %s", v)
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

// httpResp renders a 200 response whose body is body.
func httpResp(body string) string {
	return "HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

func TestRedProof_Oracle_LeakWithoutCredential(t *testing.T) {
	respB := []byte(httpResp(`{"value":"` + testValB + `"}`))
	respA := []byte(httpResp(`{"value":"` + testValA + `"}`))
	gs := genStream{topLevel: 1, methods: []string{"GET"}}
	hit := func(principal string) []handlerHit {
		return []handlerHit{{path: "/api/v1/secrets/value", principal: principal}}
	}

	// RED: secret B returned to a request that presented no credential.
	if v := evalHTTP1Oracles(gs, respB, hit(""), 0, testValA, testValB); v == "" {
		t.Fatal("leak oracle did not fire on secret B without admin credential")
	}
	// RED: secret B returned to the scoped reader (cross-tenant).
	if v := evalHTTP1Oracles(gs, respB, hit(readerUser), 0, testValA, testValB); v == "" {
		t.Fatal("leak oracle did not fire on secret B returned to the projA-scoped reader")
	}
	// GREEN: admin reading B.
	if v := evalHTTP1Oracles(gs, respB, hit(adminUser), 0, testValA, testValB); v != "" {
		t.Fatalf("leak oracle false-positived on an authorized read: %s", v)
	}
	// RED: secret A returned to an unauthenticated request.
	if v := evalHTTP1Oracles(gs, respA, hit(""), 0, testValA, testValB); v == "" {
		t.Fatal("leak oracle did not fire on secret A without any credential")
	}
	// GREEN: secret A to the scoped reader, and to admin.
	for _, p := range []string{readerUser, adminUser} {
		if v := evalHTTP1Oracles(gs, respA, hit(p), 0, testValA, testValB); v != "" {
			t.Fatalf("leak oracle false-positived on %s reading A: %s", p, v)
		}
	}
}

// TestRedProof_Oracle_LeakIsPerRequest is review finding F2: request 1 carries the
// admin token, request 2 (pipelined on the same connection) carries none yet receives
// secret B. The old connection-wide "an admin token appears somewhere" check stayed
// silent; the per-request pairing must fire, and stay silent when request 2 is admin too.
func TestRedProof_Oracle_LeakIsPerRequest(t *testing.T) {
	resp := []byte(httpResp("ok") + httpResp(`{"value":"`+testValB+`"}`))
	gs := genStream{topLevel: 2, methods: []string{"GET", "GET"}}

	// RED: admin on request 1, nothing on request 2, B in response 2.
	red := []handlerHit{{path: "/health", principal: adminUser}, {path: "/api/v1/secrets/value", principal: ""}}
	if v := evalHTTP1Oracles(gs, resp, red, 0, testValA, testValB); v == "" {
		t.Fatal("per-request leak oracle did not fire on B returned to an unauthenticated pipelined request behind an admin one")
	}
	// GREEN twin: both requests carried admin.
	green := []handlerHit{{path: "/health", principal: adminUser}, {path: "/api/v1/secrets/value", principal: adminUser}}
	if v := evalHTTP1Oracles(gs, resp, green, 0, testValA, testValB); v != "" {
		t.Fatalf("per-request leak oracle false-positived when both requests were admin: %s", v)
	}
	// RED: a secret in a response with no matching hit at all (server-generated / smuggled tail).
	if v := evalHTTP1Oracles(gs, resp, red[:1], 0, testValA, testValB); v == "" {
		t.Fatal("leak oracle did not fire on a secret in a response that has no handler hit")
	}
}

// TestRedProof_Oracle_H2LeakIsPerStream is F2 for the HTTP/2 targets: stream 1 carries
// admin, stream 3 carries nothing yet receives B.
func TestRedProof_Oracle_H2LeakIsPerStream(t *testing.T) {
	mk := func(creds map[uint32]credsSent) *h2Result {
		r := newH2Result()
		r.add(1, []byte(":status: 200\nok"))
		r.add(3, []byte(":status: 200\n"+testValB))
		maps.Copy(r.creds, creds)
		return r
	}
	// RED: admin only on stream 1.
	if v := evalH2Leak(mk(map[uint32]credsSent{1: {admin: true}}), testValA, testValB); v == "" {
		t.Fatal("per-stream leak oracle did not fire on B in a stream that carried no credential")
	}
	// RED: the reader on stream 3 (cross-tenant).
	if v := evalH2Leak(mk(map[uint32]credsSent{1: {admin: true}, 3: {reader: true}}), testValA, testValB); v == "" {
		t.Fatal("per-stream leak oracle did not fire on B returned to the scoped reader")
	}
	// GREEN twin: admin on both streams.
	if v := evalH2Leak(mk(map[uint32]credsSent{1: {admin: true}, 3: {admin: true}}), testValA, testValB); v != "" {
		t.Fatalf("per-stream leak oracle false-positived with admin on both streams: %s", v)
	}
	// RED: a secret on the connection-level pseudo stream 0 (e.g. GOAWAY debug data).
	r := newH2Result()
	r.add(0, []byte(testValA))
	if v := evalH2Leak(r, testValA, testValB); v == "" {
		t.Fatal("leak oracle did not fire on a secret in connection-level bytes")
	}
}

func TestRedProof_Oracle_ResponseSplitting(t *testing.T) {
	// RED: an injected header materialized in the first response header block.
	split := []byte("HTTP/1.1 200 OK\r\nX-Injected: 1\r\nContent-Length: 4\r\n\r\nbody")
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
	// RED: alloc delta over the cap, through the shared evaluator and through HTTP/1.
	if v := evalAlloc(wireAllocCap + 1); v == "" {
		t.Fatal("alloc oracle did not fire above the cap")
	}
	if v := evalHTTP1Oracles(genStream{topLevel: 1}, nil, nil, wireAllocCap+1, "A", "B"); v == "" {
		t.Fatal("HTTP/1 alloc oracle did not fire above the cap")
	}
	// GREEN: alloc delta under the cap.
	if v := evalAlloc(wireAllocCap - 1); v != "" {
		t.Fatalf("alloc oracle false-positived under the cap: %s", v)
	}
	if v := evalHTTP1Oracles(genStream{topLevel: 1}, nil, nil, wireAllocCap-1, "A", "B"); v != "" {
		t.Fatalf("HTTP/1 alloc oracle false-positived under the cap: %s", v)
	}
}

// preAllocSink holds the planted server's allocation so the heap delta is real.
var preAllocSink []byte

// TestRedProof_Alloc_GRPCPreAlloc watches the 4 GiB pre-alloc probe's measurement path
// fire: a PLANTED gRPC server that allocates 600 MiB as soon as a request arrives
// (the defect a server that trusted a 0xFFFFFFFF length prefix would have) is driven by
// grpcFramingDrive with the 4 GiB-claim shape inside measureAlloc, and evalAlloc must
// fire; the same input against the real server must stay under the cap. The planted
// slice is never touched (no resident growth) and is released afterwards.
func TestRedProof_Alloc_GRPCPreAlloc(t *testing.T) {
	gsrv := grpc.NewServer(grpc.UnknownServiceHandler(func(any, grpc.ServerStream) error {
		preAllocSink = make([]byte, 600<<20)
		return nil
	}))
	planted := serveGRPC(t, gsrv, &seededStack{adminTok: "adm", readTok: "rd"})
	t.Cleanup(func() { preAllocSink = nil })

	shape2 := []byte{2, 0, 0, 0} // shape 2 = 0xFFFFFFFF declared length, no credential
	http1Mu.Lock()
	defer http1Mu.Unlock()
	delta := measureAlloc(func() { _, _ = grpcFramingDrive(planted, shape2, 10*time.Second) })
	if v := evalAlloc(delta); v == "" {
		t.Fatalf("RED FAILED: pre-alloc oracle did not fire (delta=%d) against a server that allocates 600 MiB", delta)
	}
	preAllocSink = nil

	realW := buildGRPCWorld(t)
	delta = measureAlloc(func() { _, _ = grpcFramingDrive(realW, shape2, 10*time.Second) })
	if v := evalAlloc(delta); v != "" {
		t.Fatalf("GREEN FAILED: pre-alloc oracle fired against the real server: %s", v)
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
	// Broken stack: leaks valA to everyone.
	rec := &recorder{resolve: func(string) string { return "" }}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	leaky := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"value":"` + testValA + `"}`))
	})
	srv := &http.Server{Handler: rec.wrap(leaky), ReadHeaderTimeout: wireReadHeaderTimeout}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	wire := []byte("GET /api/v1/secrets/value?ref=proja/prod/sa HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
	methods := []string{"GET"}
	resp, timedOut := exchange(ln.Addr().String(), wire, methods, 1, 5*time.Second)
	if timedOut {
		t.Fatal("broken stack timed out")
	}
	if !bytes.Contains(resp, []byte(testValA)) {
		t.Fatalf("precondition failed: broken stack did not actually return the plaintext; resp=%q", truncate(resp, 400))
	}
	gs := genStream{wire: wire, topLevel: 1, methods: methods} // no credential on the wire
	if v := evalHTTP1Oracles(gs, resp, rec.snapshot(), 0, testValA, testValB); v == "" {
		t.Fatal("RED FAILED: leak oracle did not fire against a listener that leaks the plaintext unauthenticated")
	}

	// GREEN control: the real stack, same unauthenticated request, must be clean.
	w := buildWireWorld(t)
	w.rec.reset()
	resp2, timedOut2 := exchange(w.addr, wire, methods, 1, 5*time.Second)
	if timedOut2 {
		t.Fatal("real stack timed out")
	}
	if v := evalHTTP1Oracles(gs, resp2, w.rec.snapshot(), 0, w.valA, w.valB); v != "" {
		t.Fatalf("GREEN FAILED: oracle fired against the real stack for an unauthenticated /secrets read: %s\nresp=%q", v, truncate(resp2, 400))
	}
}

// plantedSeed is a seededStack with fixed tokens/ids and no database, for planted servers.
func plantedSeed() *seededStack {
	return &seededStack{
		adminTok: "planted-admin-token", readTok: "planted-reader-token",
		refA: "proja/prod/sa", valA: testValA, refB: "projb/prod/sb", valB: testValB,
		idA: 1, idB: 2,
	}
}

// leakyGRPC returns a gRPC server that answers EVERY call, authenticated or not, with
// secret B's plaintext in a protobuf string field.
func leakyGRPC() *grpc.Server {
	return grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		return stream.SendMsg(wrapperspb.String(testValB))
	}))
}

// TestRedProof_PlantedLeak_HTTP2 drives a gRPC server that leaks B to everyone through
// FuzzWireHTTP2's own driver with the reader-reads-B input; the per-stream oracle must
// fire. (The real stack's green twin is TestAntiVacuity_HTTP2.)
func TestRedProof_PlantedLeak_HTTP2(t *testing.T) {
	w := serveGRPC(t, leakyGRPC(), plantedSeed())
	res, timedOut := h2Drive(w, []byte{1, 0, 3, 0, 1, 1, 1, 1}, 10*time.Second) // reader, GetSecretValue, valid request for B
	if timedOut {
		t.Fatal("planted server timed out")
	}
	if !bytes.Contains(res.all(), []byte(testValB)) {
		t.Fatalf("precondition failed: planted server did not return B through the driver; got %q", truncate(res.all(), 300))
	}
	if v := evalH2Leak(res, testValA, testValB); v == "" {
		t.Fatal("RED FAILED: per-stream leak oracle did not fire on a server that leaks B to the reader")
	}
}

// TestRedProof_PlantedLeak_GRPCFraming is the same for FuzzWireGRPCFraming's driver.
func TestRedProof_PlantedLeak_GRPCFraming(t *testing.T) {
	w := serveGRPC(t, leakyGRPC(), plantedSeed())
	res, timedOut := grpcFramingDrive(w, []byte{5, 3, 0, 0, 1}, 10*time.Second) // shape 5 (valid msg), reader, secret B
	if timedOut {
		t.Fatal("planted server timed out")
	}
	if !bytes.Contains(res.all(), []byte(testValB)) {
		t.Fatalf("precondition failed: planted server did not return B through the driver; got %q", truncate(res.all(), 300))
	}
	if v := evalH2Leak(res, testValA, testValB); v == "" {
		t.Fatal("RED FAILED: per-stream leak oracle did not fire on a server that leaks B to the reader")
	}
}

// TestRedProof_PlantedLeak_HTTP2TLS is the same for FuzzWireHTTP2TLS's driver: a TLS+h2
// listener whose handler leaks B to every request.
func TestRedProof_PlantedLeak_HTTP2TLS(t *testing.T) {
	leaky := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"value":"` + testValB + `"}`))
	})
	w := serveTLSHandler(t, leaky, plantedSeed())
	res, _, timedOut := tlsH2Drive(w, []byte{0, 0, 3, 2}, 10*time.Second) // reader GET secret B
	if timedOut {
		t.Fatal("planted server timed out")
	}
	if !bytes.Contains(res.all(), []byte(testValB)) {
		t.Fatalf("precondition failed: planted server did not return B through the driver; got %q", truncate(res.all(), 300))
	}
	if v := evalH2Leak(res, testValA, testValB); v == "" {
		t.Fatal("RED FAILED: per-stream leak oracle did not fire on a server that leaks B to the reader")
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

// serveBareH2 serves handler on a bare x/net/http2 server (no net/http listener), so
// the SETTINGS frame is sent on connect but the handler decides whether a request is
// ever answered. It returns the address and a stop func.
func serveBareH2(t *testing.T, handler http.Handler) (addr string, stop func()) {
	t.Helper()
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
			go h2s.ServeConn(c, &http2.ServeConnOpts{Handler: handler}) //nolint:staticcheck // SA1019: see above
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close(); <-done }
}

// TestRedProof_GRPCHealthProbe watches grpcHealthProbe return nil against a live HTTP/2
// listener that answers the RPC with a grpc-status (GREEN), a non-nil error once the
// listener is closed (RED), and a non-nil error against a listener that completes the
// HTTP/2 handshake and sends SETTINGS but never answers a request (RED: the wedged
// handler case a bare SETTINGS exchange could not see).
func TestRedProof_GRPCHealthProbe(t *testing.T) {
	addr, stop := serveBareH2(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Grpc-Status", "16")
		w.WriteHeader(http.StatusOK)
	}))
	// GREEN: live HTTP/2 listener answers with a grpc-status.
	if err := grpcHealthProbe(addr); err != nil {
		t.Fatalf("GREEN FAILED: gRPC probe errored against a live HTTP/2 listener: %v", err)
	}
	// RED: closed listener refuses a fresh connection.
	stop()
	if err := grpcHealthProbe(addr); err == nil {
		t.Fatal("RED FAILED: gRPC health probe passed against a closed listener")
	}

	// RED: SETTINGS are sent, the request is never answered.
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	wedged, stopWedged := serveBareH2(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer stopWedged()
	if err := grpcHealthProbe(wedged); err == nil {
		t.Fatal("RED FAILED: gRPC health probe passed against a listener that never serves a request")
	}
}

// --- TLS + ALPN HTTP/2-on-the-HTTP-listener reachability -------------------------

// TestRedProof_TLSALPNReachability proves the FuzzWireHTTP2TLS target is NOT vacuous:
// the TLS listener actually negotiates ALPN "h2" (GREEN), and a well-formed HTTP/2
// request to /health over that connection reaches net/http's HTTP/2 server and returns
// a real response. It also asserts the vacuity guard fires: an h2-less client (ALPN
// "http/1.1" only) does NOT negotiate h2, which the driver would flag.
func TestRedProof_TLSALPNReachability(t *testing.T) {
	w := buildTLSWireWorld(t)

	// GREEN: an h2 client negotiates h2 and the probe (a real GET /health) succeeds.
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
// listener (GREEN), a non-nil error against a dead port (RED), and a non-nil error
// against a TLS+h2 listener that accepts connections and negotiates h2 but whose
// handler never answers (RED: a wedged handler pool a bare SETTINGS round-trip passes).
func TestRedProof_TLSHealthProbe(t *testing.T) {
	w := buildTLSWireWorld(t)
	if err := tlsH2HealthProbe(w.addr, w.clientCfg); err != nil {
		t.Fatalf("GREEN FAILED: TLS health probe errored against a live listener: %v", err)
	}
	// RED: dial a definitely-closed port on loopback by grabbing and releasing one.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close() // port now refuses connections
	if err := tlsH2HealthProbe(deadAddr, w.clientCfg); err == nil {
		t.Fatal("RED FAILED: TLS health probe passed against a closed port")
	}
	// RED: accepts + negotiates h2, never answers.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	wedged := serveTLSHandler(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-ctx.Done():
		case <-r.Context().Done():
		}
	}), plantedSeed())
	if err := tlsH2HealthProbe(wedged.addr, wedged.clientCfg); err == nil {
		t.Fatal("RED FAILED: TLS health probe passed against a listener that never serves a request")
	}
}

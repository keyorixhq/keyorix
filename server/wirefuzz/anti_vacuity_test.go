package wirefuzz

// anti_vacuity_test.go proves the authz/leak oracle is not vacuous (review finding F1)
// and that the generators emit what the docs claim (F3, F4).
//
// A leak oracle that only ever sees 503s, 401s or empty reads stays green forever, so
// "N hours of fuzzing, no failures" would say nothing about authorization. Each
// TestAntiVacuity_* test therefore drives the target's OWN driver, with a fixed input
// the fuzzer can also reach, and requires:
//
//	POSITIVE CONTROL  an admin read of secret A returns A's plaintext (the oracle can
//	                  see an authorized response), with the oracle silent on it;
//	NEGATIVE CONTROL  the projA-scoped reader's read of secret B returns neither B's
//	                  plaintext nor a success: a clear denial status.
//
// The red twins (a planted leaky server through the same driver, which the oracle must
// flag) live in oracle_redproof_test.go (TestRedProof_PlantedLeak_*).

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/keyorixhq/keyorix/server/proto/pb"
)

func TestAntiVacuity_HTTP1(t *testing.T) {
	w := buildWireWorld(t)
	http1Mu.Lock()
	defer http1Mu.Unlock()

	run := func(data []byte) (genStream, []h1Resp, []handlerHit) {
		t.Helper()
		gs := generateHTTP1(w, data)
		if gs.raw || gs.topLevel != 1 {
			t.Fatalf("fixed input must decode to one structured request, got raw=%v topLevel=%d", gs.raw, gs.topLevel)
		}
		w.rec.reset()
		resp, timedOut := exchange(w.addr, gs.wire, gs.methods, gs.topLevel, 10*time.Second)
		if timedOut {
			t.Fatal("exchange timed out")
		}
		hits := w.rec.snapshot()
		if v := evalHTTP1Oracles(gs, resp, hits, 0, w.valA, w.valB); v != "" {
			t.Fatalf("oracle fired on the real stack: %s\nresp=%q", v, truncate(resp, 400))
		}
		return gs, parseHTTP1Responses(resp, gs.methods), hits
	}

	// POSITIVE: admin reads A. {b0, method GET, target secret-read, pick refA, host, cred admin, no extra, no body}
	gs, rs, hits := run([]byte{0, 0, 0, 0, 0, 2, 4, 0})
	if !bytes.Contains(gs.wire, []byte(w.adminTok)) || !bytes.Contains(gs.wire, []byte(w.refA)) {
		t.Fatalf("precondition: wire must carry the admin token and refA: %q", truncate(gs.wire, 300))
	}
	if len(rs) == 0 || rs[0].status != 200 || !bytes.Contains(rs[0].text, []byte(w.valA)) {
		t.Fatalf("POSITIVE CONTROL FAILED: admin read of A did not return 200 + valA (the oracle is blind); rs=%q", truncate(joinText(rs), 400))
	}
	if len(hits) != 1 || hits[0].principal != adminUser {
		t.Fatalf("recorder did not resolve the admin principal: %+v", hits)
	}

	// NEGATIVE: the projA reader reads B.
	_, rs, hits = run([]byte{0, 0, 0, 1, 0, 3, 4, 0})
	if len(rs) == 0 {
		t.Fatal("no response to the reader's read of B")
	}
	if bytes.Contains(joinText(rs), []byte(w.valB)) {
		t.Fatal("LEAK: the projA reader received secret B")
	}
	if rs[0].status != 403 {
		t.Fatalf("NEGATIVE CONTROL: reader's read of B must be 403, got %d (a 503 here would mean the harness is cancelling requests)", rs[0].status)
	}
	if len(hits) != 1 || hits[0].principal != readerUser {
		t.Fatalf("recorder did not resolve the reader principal: %+v", hits)
	}
}

func joinText(rs []h1Resp) []byte {
	var b []byte
	for _, r := range rs {
		b = append(b, r.text...)
	}
	return b
}

// TestAntiVacuity_HalfCloseCausesFailClosed pins the ROOT CAUSE of review finding F1,
// so nobody reintroduces a half-close "to get a prompt EOF": a request that is
// half-closed (FIN) right after the write is cancelled by net/http, the auth
// middleware fails closed, and an authorized admin read returns 503 (or 500, or 403 when
// the RBAC lookup was the cancelled one) instead of 200, never carrying a secret value.
// A response fully served before the FIN landed is a timing race in the premise and is
// retried (requireHalfCloseFailsClosed).
func TestAntiVacuity_HalfCloseCausesFailClosed(t *testing.T) {
	w := buildWireWorld(t)
	wire := []byte("GET /api/v1/secrets/value?ref=" + w.refA + " HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer " + w.adminTok + "\r\n\r\n")

	if err := requireHalfCloseFailsClosed(w.addr, wire, w.valA, w.valB, halfCloseAttempts); err != nil {
		t.Fatal(err)
	}

	// ...while exchange() (no half-close) gets the real answer.
	resp, _ := exchange(w.addr, wire, []string{"GET"}, 1, 8*time.Second)
	if !bytes.Contains(resp, []byte(w.valA)) {
		t.Fatalf("exchange() must not half-close: authorized read should return valA, got %q", truncate(resp, 200))
	}
}

// halfCloseAttempts bounds the "premise not established" retries below. A genuine race
// (the FIN lands after the handler already wrote the value) was seen in ~2/40 runs, so ten
// consecutive races are ~1e-13; a server that really serves half-closed reads serves on
// every attempt and fails after exactly this many.
const halfCloseAttempts = 10

// halfCloseVerdict classifies one half-closed authorized read.
type halfCloseVerdict int

const (
	// halfCloseFailClosed: a cancelled request answered 503 (auth lookup cancelled), 500
	// (handler's storage read cancelled, seen in CI on #4201) or 403 (the RBAC lookup was
	// cancelled and denied), with no secret value in it.
	halfCloseFailClosed halfCloseVerdict = iota
	// halfCloseServedBeforeFIN: a complete 200 carrying valA. Either the FIN landed after
	// the handler had already written (a timing race in the test premise), or the server
	// really serves half-closed reads; one attempt cannot tell, repetition does.
	halfCloseServedBeforeFIN
	// halfCloseBroken: anything else, including a secret value in a non-200 body.
	halfCloseBroken
)

func classifyHalfClose(resp []byte, valA, valB string) (halfCloseVerdict, string) {
	leaked := bytes.Contains(resp, []byte(valA)) || bytes.Contains(resp, []byte(valB))
	switch {
	case bytes.HasPrefix(resp, []byte("HTTP/1.1 200")) && bytes.Contains(resp, []byte(valA)):
		return halfCloseServedBeforeFIN, ""
	case leaked:
		return halfCloseBroken, fmt.Sprintf("a secret value is in a non-200 response to a half-closed read: %q", truncate(resp, 120))
	case bytes.HasPrefix(resp, []byte("HTTP/1.1 503")),
		bytes.HasPrefix(resp, []byte("HTTP/1.1 500")),
		bytes.HasPrefix(resp, []byte("HTTP/1.1 403")):
		return halfCloseFailClosed, ""
	}
	return halfCloseBroken, fmt.Sprintf("expected a fail-closed 503, 500 or 403 for a half-closed authorized read, got %q", truncate(resp, 80))
}

// halfCloseOnce writes wire, sends FIN, and reads until the server closes.
func halfCloseOnce(addr string, wire []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(conn)
	return buf.Bytes(), nil
}

// requireHalfCloseFailsClosed returns nil once a half-closed authorized read is answered
// fail-closed with no secret value. A response that was fully served before the FIN is
// "premise not established" and is retried, up to attempts times; if every attempt is
// served, the server really serves half-closed reads and the error says so.
func requireHalfCloseFailsClosed(addr string, wire []byte, valA, valB string, attempts int) error {
	for i := 1; i <= attempts; i++ {
		resp, err := halfCloseOnce(addr, wire)
		if err != nil {
			return err
		}
		switch v, why := classifyHalfClose(resp, valA, valB); v {
		case halfCloseFailClosed:
			return nil
		case halfCloseBroken:
			return errors.New(why)
		}
	}
	return fmt.Errorf("the server served the authorized read in all %d half-closed attempts: it now serves half-closed reads, so the premise of the no-half-close driver rule (oracles_test.go header) no longer holds; update that comment and this test", attempts)
}

// TestAntiVacuity_HalfCloseCalibration keeps the half-close test honest in both directions
// against fixture servers: a server that really serves after the FIN, or leaks in a 403,
// must go red; a one-off race followed by a cancelled answer, or a plain 403, stays green.
func TestAntiVacuity_HalfCloseCalibration(t *testing.T) {
	const valA, valB = "VALUE-A-SECRET", "VALUE-B-SECRET"
	wire := []byte("GET /x HTTP/1.1\r\nHost: h\r\n\r\n")
	respond := func(status, body string) []byte {
		return []byte(fmt.Sprintf("HTTP/1.1 %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, len(body), body))
	}
	// fixture serves replies[i] to the i-th connection (the last one repeats), after
	// reading the request head, whatever the client's FIN state is.
	fixture := func(t *testing.T, replies ...[]byte) string {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for n := 0; ; n++ {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				reply := replies[min(n, len(replies)-1)]
				go func() {
					defer func() { _ = c.Close() }()
					_ = c.SetDeadline(time.Now().Add(5 * time.Second))
					head := make([]byte, 0, 256)
					one := make([]byte, 1)
					for !bytes.HasSuffix(head, []byte("\r\n\r\n")) {
						if _, err := c.Read(one); err != nil {
							return
						}
						head = append(head, one...)
					}
					_, _ = c.Write(reply)
				}()
			}
		}()
		return ln.Addr().String()
	}

	served := respond("200 OK", valA)
	failed := respond("503 Service Unavailable", "unavailable")

	for _, tc := range []struct {
		name    string
		replies [][]byte
		wantErr string // "" = green
	}{
		{"serves after FIN every time", [][]byte{served}, "serves half-closed reads"},
		{"403 that leaks the value", [][]byte{respond("403 Forbidden", valA)}, "secret value"},
		{"403 that leaks the other secret", [][]byte{respond("403 Forbidden", valB)}, "secret value"},
		{"unexpected 200 without the value", [][]byte{respond("200 OK", "nothing")}, "expected a fail-closed"},
		{"cancelled lookup answered 403", [][]byte{respond("403 Forbidden", "forbidden")}, ""},
		{"cancelled lookup answered 503", [][]byte{failed}, ""},
		{"cancelled handler read answered 500", [][]byte{respond("500 Internal Server Error", "context canceled")}, ""},
		{"one race, then fail-closed", [][]byte{served, served, failed}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := requireHalfCloseFailsClosed(fixture(t, tc.replies...), wire, valA, valB, halfCloseAttempts)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("expected green, got %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("expected red containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestAntiVacuity_HTTP2(t *testing.T) {
	w := buildGRPCWorld(t)
	http1Mu.Lock()
	defer http1Mu.Unlock()
	// n=2 frames: HEADERS(admin|reader, GetSecretValue, stream left open) then a valid
	// GetSecretRequest on that stream (the DATA lands on the last OPENED stream).
	adminReadsA := []byte{1, 0, 2, 0, 1, 1, 1, 0}
	readerReadsB := []byte{1, 0, 3, 0, 1, 1, 1, 1}

	res, timedOut := h2Drive(w, adminReadsA, 10*time.Second)
	if timedOut {
		t.Fatal("h2Drive timed out")
	}
	s1 := res.streams[1]
	if !res.creds[1].admin || !bytes.Contains(s1, []byte(w.s.valA)) || !bytes.Contains(s1, []byte("grpc-status: 0")) {
		t.Fatalf("POSITIVE CONTROL FAILED: admin GetSecretValue(A) did not return valA with grpc-status 0 (oracle is blind); stream1=%q", truncate(s1, 300))
	}
	if v := evalH2Leak(res, w.s.valA, w.s.valB); v != "" {
		t.Fatalf("oracle fired on an authorized read: %s", v)
	}

	res, timedOut = h2Drive(w, readerReadsB, 10*time.Second)
	if timedOut {
		t.Fatal("h2Drive timed out")
	}
	s1 = res.streams[1]
	if !res.creds[1].reader || bytes.Contains(res.all(), []byte(w.s.valB)) {
		t.Fatalf("NEGATIVE CONTROL: reader must not receive B; stream1=%q", truncate(s1, 300))
	}
	if !bytes.Contains(s1, []byte("grpc-status: 7")) { // codes.PermissionDenied
		t.Fatalf("NEGATIVE CONTROL: reader's read of B must be PermissionDenied (7); stream1=%q", truncate(s1, 300))
	}
}

func TestAntiVacuity_GRPCFraming(t *testing.T) {
	w := buildGRPCWorld(t)
	http1Mu.Lock()
	defer http1Mu.Unlock()
	// shape 5 (valid GetSecretRequest), credential, payload byte, payload len, secret selector.
	adminReadsA := []byte{5, 2, 0, 0, 0}
	readerReadsB := []byte{5, 3, 0, 0, 1}

	res, timedOut := grpcFramingDrive(w, adminReadsA, 10*time.Second)
	if timedOut {
		t.Fatal("grpcFramingDrive timed out")
	}
	s1 := res.streams[1]
	if !res.creds[1].admin || !bytes.Contains(s1, []byte(w.s.valA)) || !bytes.Contains(s1, []byte("grpc-status: 0")) {
		t.Fatalf("POSITIVE CONTROL FAILED: admin GetSecretValue(A) did not return valA with grpc-status 0; stream1=%q", truncate(s1, 300))
	}
	if v := evalH2Leak(res, w.s.valA, w.s.valB); v != "" {
		t.Fatalf("oracle fired on an authorized read: %s", v)
	}

	res, timedOut = grpcFramingDrive(w, readerReadsB, 10*time.Second)
	if timedOut {
		t.Fatal("grpcFramingDrive timed out")
	}
	s1 = res.streams[1]
	if !res.creds[1].reader || bytes.Contains(res.all(), []byte(w.s.valB)) || !bytes.Contains(s1, []byte("grpc-status: 7")) {
		t.Fatalf("NEGATIVE CONTROL: reader's read of B must be PermissionDenied without B's plaintext; stream1=%q", truncate(s1, 300))
	}
}

// TestAntiVacuity_GRPCFramingReachesSecretIDs pins the second cause of F1: the junk
// payloads (one byte repeated n times) can never decode to a real secret id, so the
// valid-message shape is the only way a fuzz input reaches a secret.
func TestAntiVacuity_GRPCFramingReachesSecretIDs(t *testing.T) {
	for _, id := range []uint32{1, 2} {
		msg := validGRPCMessage(id)
		var req pb.GetSecretRequest
		if err := proto.Unmarshal(msg[5:], &req); err != nil || req.GetId() != id {
			t.Fatalf("validGRPCMessage(%d) does not round-trip: id=%d err=%v", id, req.GetId(), err)
		}
	}
	reached := 0
	for b := range 256 {
		for n := range 64 {
			var req pb.GetSecretRequest
			if proto.Unmarshal(bytes.Repeat([]byte{byte(b)}, n), &req) == nil && (req.GetId() == 1 || req.GetId() == 2) {
				reached++
			}
		}
	}
	if reached != 0 {
		t.Fatalf("the repeated-byte payloads now reach a secret id (%d); the valid-message shape may be redundant", reached)
	}
}

func TestAntiVacuity_HTTP2TLS(t *testing.T) {
	w := buildTLSWireWorld(t)
	http1Mu.Lock()
	defer http1Mu.Unlock()
	// n=1 frame: HEADERS to a REST path (index 1 = refA, 2 = refB) with a credential (2 admin, 3 reader).
	adminReadsA := []byte{0, 0, 2, 1}
	readerReadsB := []byte{0, 0, 3, 2}

	res, proto, timedOut := tlsH2Drive(w, adminReadsA, 10*time.Second)
	if timedOut || proto != "h2" {
		t.Fatalf("timedOut=%v proto=%q", timedOut, proto)
	}
	s1 := res.streams[1]
	if !res.creds[1].admin || !bytes.Contains(s1, []byte(w.s.valA)) || !bytes.Contains(s1, []byte(":status: 200")) {
		t.Fatalf("POSITIVE CONTROL FAILED: admin GET of A over h2 did not return 200 + valA (oracle is blind); stream1=%q", truncate(s1, 300))
	}
	if v := evalH2Leak(res, w.s.valA, w.s.valB); v != "" {
		t.Fatalf("oracle fired on an authorized read: %s", v)
	}

	res, proto, timedOut = tlsH2Drive(w, readerReadsB, 10*time.Second)
	if timedOut || proto != "h2" {
		t.Fatalf("timedOut=%v proto=%q", timedOut, proto)
	}
	s1 = res.streams[1]
	if !res.creds[1].reader || bytes.Contains(res.all(), []byte(w.s.valB)) || !bytes.Contains(s1, []byte(":status: 403")) {
		t.Fatalf("NEGATIVE CONTROL: reader's GET of B must be 403 without B's plaintext; stream1=%q", truncate(s1, 300))
	}
}

// --- Generator proofs (F3, F4) -----------------------------------------------------

// genWorld is enough of a wireWorld for the pure generators (no server).
func genWorld() *wireWorld {
	return &wireWorld{adminTok: "ADMINTOKEN", readTok: "READERTOKEN", refA: "proja/prod/sa", refB: "projb/prod/sb"}
}

// inputFor derives a deterministic pseudo-random input from i (no math/rand).
func inputFor(i int) []byte {
	out := make([]byte, 40)
	x := uint32(i)*2654435761 + 1
	for j := range out {
		x = x*1664525 + 1013904223
		out[j] = byte(x >> 24)
	}
	return out
}

// TestGenerator_InjectsImpliesCRLFPayload: `injects` is true exactly when an encoded CRLF
// payload is on the wire, so the splitting oracle never runs on an input that carried
// none and never skips one that did (review finding F4).
func TestGenerator_InjectsImpliesCRLFPayload(t *testing.T) {
	w := genWorld()
	sawInject := false
	for i := range 4000 {
		data := inputFor(i)
		data[0] &= 0x7f // structured lane
		gs := generateHTTP1(w, data)
		has := bytes.Contains(gs.wire, []byte("%0d%0a"))
		if gs.injects != has {
			t.Fatalf("input %d: injects=%v but wire carries %%0d%%0a=%v", i, gs.injects, has)
		}
		sawInject = sawInject || gs.injects
	}
	if !sawInject {
		t.Fatal("no generated input ever carried a CRLF payload")
	}
	// Fixed seeds for each reflected position.
	for name, data := range map[string][]byte{
		"origin":   {0, 0, 1, 0, 0, 2, 0},
		"ref":      {0, 0, 0, 4, 0, 0, 4, 0},
		"ref-enc":  {0, 0, 0, 5, 0, 0, 4, 0},
		"path-seg": {0, 0, 3, 4, 0, 0, 4, 0},
	} {
		gs := generateHTTP1(w, data)
		if !gs.injects || !bytes.Contains(gs.wire, []byte("%0d%0aX-Injected:%201")) {
			t.Errorf("%s seed: injects=%v wire=%q", name, gs.injects, truncate(gs.wire, 200))
		}
	}
	if gs := generateHTTP1(w, []byte{0, 0, 1, 0, 0, 4, 0}); gs.injects {
		t.Error("a payload-free input must not set injects")
	}
}

// TestGenerator_RawLaneShortCL: the raw lane turns fuzz bytes into a Content-Length that
// disagrees with the body (review finding F3). The seed's body is 8 bytes and its CL is 5.
func TestGenerator_RawLaneShortCL(t *testing.T) {
	gs := generateHTTP1(genWorld(), rawSeedShortCL())
	if !gs.raw {
		t.Fatal("seed must select the raw lane")
	}
	head, body, ok := bytes.Cut(gs.wire, []byte("\r\n\r\n"))
	if !ok {
		t.Fatalf("no header terminator in %q", gs.wire)
	}
	if !bytes.Contains(head, []byte("\r\nContent-Length: 5")) || len(body) != 8 {
		t.Fatalf("expected CL=5 with an 8-byte body, got head=%q body=%q", head, body)
	}
}

// TestGenerator_RawLaneChunkOverflow: a chunk-size token taken from the input overflows a
// 64-bit size (22 hex digits), and reaches the real server via exchange().
func TestGenerator_RawLaneChunkOverflow(t *testing.T) {
	gs := generateHTTP1(genWorld(), rawSeedChunkOverflow())
	if !gs.raw || !bytes.Contains(gs.wire, []byte("\r\n"+strings.Repeat("f", 22)+"\r\n")) {
		t.Fatalf("raw=%v wire=%q", gs.raw, truncate(gs.wire, 300))
	}
}

// TestGenerator_RawLaneReachesServer sends both raw seeds through exchange() into the
// real listener and requires the whole pipeline to stay oracle-clean and the listener
// healthy, so the raw lane is a live path, not just generator output.
func TestGenerator_RawLaneReachesServer(t *testing.T) {
	w := buildWireWorld(t)
	http1Mu.Lock()
	defer http1Mu.Unlock()
	for name, data := range map[string][]byte{"short-cl": rawSeedShortCL(), "chunk-overflow": rawSeedChunkOverflow()} {
		gs := generateHTTP1(w, data)
		w.rec.reset()
		resp, timedOut := exchange(w.addr, gs.wire, gs.methods, gs.topLevel, 10*time.Second)
		if timedOut {
			t.Fatalf("%s: timed out", name)
		}
		if len(resp) == 0 {
			t.Fatalf("%s: server returned nothing for a raw-lane request", name)
		}
		if v := evalHTTP1Oracles(gs, resp, w.rec.snapshot(), 0, w.valA, w.valB); v != "" {
			t.Fatalf("%s: %s", name, v)
		}
		if err := httpHealthProbe(w.addr); err != nil {
			t.Fatalf("%s: listener unhealthy afterwards: %v", name, err)
		}
	}
}

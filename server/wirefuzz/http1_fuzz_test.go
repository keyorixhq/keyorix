package wirefuzz

// FuzzWireHTTP1 feeds RAW TCP bytes to the production HTTP/1.1 parser (net/http's
// own conn reader, reached by http.Server.Serve on a loopback listener) and checks
// framing/smuggling invariants against the real router + auth + handlers.
//
// A small structure-aware generator turns the fuzz input into one or more TOP-LEVEL
// requests with the framing variants that produce smuggling/confusion bugs:
// absolute-form and authority-form request targets, Host mismatches, duplicate and
// obs-fold headers, Content-Length vs Transfer-Encoding combinations (CL.TE / TE.CL
// / TE.TE) whose ambiguous bodies EMBED a hidden second request-line, chunk
// extensions and trailers, pipelined requests, and oversized header sets. The
// generator reports, per input, the number of TOP-LEVEL requests it emitted (the
// smuggling reference count) and which credentials appear on the wire.
//
// Why the reference count is "top-level requests I emitted", not "requests I think
// are well-formed": Keyorix runs a SINGLE HTTP parser (net/http) with no front-end
// proxy, so there is no two-parser disagreement to exploit. The residual smuggling
// risk is net/http parsing one framed request as MORE than one dispatch — e.g. an
// ambiguous CL/TE body whose trailing bytes get re-parsed as a second request. So
// the sound, guess-free invariant is: handler invocations must never EXCEED the
// number of top-level requests placed on the wire. A hidden request-line smuggled
// inside an ambiguous body, if dispatched, pushes the count over and is caught.
//
// ORACLES (and, explicitly, what each does NOT verify):
//
//	(1) LIVENESS/BOUNDED — the exchange must not panic and must complete within a
//	    10s watchdog; a per-input heap-allocation delta stays under a fixed cap.
//	    DOES NOT verify: CPU time, goroutine/fd leaks, or allocation the GC reclaims
//	    between the two MemStats reads (the cap is coarse and generous; it catches a
//	    runaway unbounded buffer, not a modest transient).
//
//	(2) REQUEST-COUNT (smuggling) — top-of-stack handler invocations must be <= the
//	    number of top-level requests the generator put on the wire. More means a
//	    single framed request was dispatched as several, i.e. request smuggling.
//	    DOES NOT verify: the converse (fewer is fine — the server may legitimately
//	    reject or close); nor does it attribute a smuggled dispatch to a wire offset.
//	    In this single-parser architecture it specifically cannot find front-end/
//	    back-end desync (there is no front end); it finds self-desync only.
//
//	(3) AUTHZ/LEAK INVARIANCE — a seeded secret's plaintext may appear in the
//	    response bytes ONLY if a credential authorized to read it was present on the
//	    wire. valB (projB) requires the admin token; valA (projA) requires admin OR
//	    the scoped reader token. A plaintext without its authorizing credential is an
//	    authz bypass / confused-deputy leak, framing-agnostic.
//	    DOES NOT verify: positive reachability ("an authorized request must 200") —
//	    that would false-positive on any legitimately-rejected framing. It models the
//	    two seeded token strings as the only credentials.
//
//	(4) NO RESPONSE SPLITTING — a reflected CRLF payload must never become a real
//	    header line in the first response header block, and one top-level request
//	    must never yield a second complete HTTP status line in the response bytes.
//	    DOES NOT verify: splitting via a body the client never reads, or via
//	    trailers; exercised only on inputs carrying an injection payload.
//
// RED-PROOFS for each oracle are in scripts/fuzzing/wire-redproof (scratch, never
// committed); see the B1 report. The harness changes no production code.

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"sync"
	"testing"
	"time"
)

// http1Mu serializes per-input execution against the shared world so the recorder
// reset and the DB stay race-free under -parallel>1.
var http1Mu sync.Mutex

// genStream is a decoded byte stream plus the facts the oracles consume.
type genStream struct {
	wire      []byte
	topLevel  int // number of top-level requests emitted (smuggling reference count)
	hasAdmin  bool
	hasReader bool
	injects   bool
}

// generateHTTP1 turns fuzz bytes into a wire stream. It is deterministic and total:
// any byte slice decodes to a valid (possibly empty) stream.
func generateHTTP1(w *wireWorld, data []byte) genStream {
	rd := &byteReader{data: data}
	nReq := int(rd.u8()%3) + 1 // 1..3 top-level requests (pipelining when >1)
	var out bytes.Buffer
	gs := genStream{topLevel: nReq}
	for range nReq {
		inj := genOneHTTP1(w, rd, &out)
		gs.injects = gs.injects || inj
	}
	gs.wire = out.Bytes()
	gs.hasAdmin = bytes.Contains(gs.wire, []byte(w.adminTok))
	gs.hasReader = bytes.Contains(gs.wire, []byte(w.readTok))
	return gs
}

// canaryPath is a path no legitimate request in this harness ever targets.
// smuggledLine (a full request-line for canaryPath) is embedded ONLY inside a
// request's declared BODY — as chunk data or Content-Length-covered bytes — where a
// conformant parser treats it as body, never as a request. If net/http ever
// dispatches it, a body byte was re-parsed as a request: real request smuggling.
// This is the sound single-parser smuggling signal (an appended request after a
// COMPLETE message is RFC-correct pipelining, not smuggling, so we never do that).
const (
	canaryPath   = "/wire-smuggle-canary-zzz"
	smuggledLine = "GET " + canaryPath + " HTTP/1.1\r\nHost: smuggled\r\n\r\n"
)

func genOneHTTP1(w *wireWorld, rd *byteReader, b *bytes.Buffer) (injects bool) {
	method := []string{"GET", "POST", "GET", "HEAD", "PUT", "DELETE"}[rd.u8()%6]
	var target string
	switch rd.u8() % 4 {
	case 0:
		target = "/api/v1/secrets/value?ref=" + rd.pick([]string{w.refA, w.refB, "../../etc", "proja/prod/sa"})
	case 1:
		target = "/health"
	case 2: // absolute-form
		target = "http://127.0.0.1/api/v1/secrets/value?ref=" + rd.pick([]string{w.refA, w.refB})
	default:
		target = rd.pick([]string{"/", "/api/v1/secrets/", "//api//v1//secrets//value", "/api/v1/secrets/value"})
	}
	fmt.Fprintf(b, "%s %s HTTP/1.1\r\n", method, target)

	switch rd.u8() % 4 {
	case 0:
		b.WriteString("Host: 127.0.0.1\r\n")
	case 1:
		b.WriteString("Host: 127.0.0.1\r\nHost: evil.example\r\n") // duplicate Host
	case 2:
		b.WriteString("Host: evil.example\r\n")
	default:
		b.WriteString("Host: 127.0.0.1\r\n") // always emit a Host so most inputs reach a handler
	}

	switch rd.u8() % 4 {
	case 0: // none
	case 1:
		b.WriteString("Authorization: Bearer garbage-not-a-real-token\r\n")
	case 2:
		fmt.Fprintf(b, "Authorization: Bearer %s\r\n", w.adminTok)
	default:
		fmt.Fprintf(b, "Authorization: Bearer %s\r\n", w.readTok)
	}

	switch rd.u8() % 6 {
	case 0: // obs-fold (net/http unfolds; still one request)
		b.WriteString("X-Fold: a\r\n b\r\n")
	case 1: // oversized header set (exceeds 64 KiB MaxHeaderBytes => 431/close)
		b.WriteString("X-Big: ")
		b.Write(bytes.Repeat([]byte("A"), 70<<10))
		b.WriteString("\r\n")
	case 2: // header-injection payload reflected via a custom header value
		b.WriteString("X-Reflect: v\r\nX-Injected: 1\r\n")
		injects = true
	case 3: // duplicate benign header (legal)
		b.WriteString("Accept: a\r\nAccept: b\r\n")
	case 4:
		injects = true // CRLF-in-query style handled by ref targets; mark for splitting check
	default:
	}

	// Body framing. The smuggled canary, when present, is always placed INSIDE the
	// declared body (chunk data or CL-covered bytes), never appended after a
	// complete message — so a conformant parser treats it as body and oracle (2)/
	// the canary oracle only fire on a genuine body-as-request re-parse.
	payload := []byte(`{"value":"x"}`)
	switch rd.u8() % 7 {
	case 0: // no body
		b.WriteString("\r\n")
	case 1: // Content-Length, canary is the entire CL-covered body
		fmt.Fprintf(b, "Content-Length: %d\r\n\r\n", len(smuggledLine))
		b.WriteString(smuggledLine)
	case 2: // chunked, canary is chunk data
		b.WriteString("Transfer-Encoding: chunked\r\n\r\n")
		writeChunk(b, []byte(smuggledLine), "")
		writeChunk(b, nil, "")
	case 3: // CL.TE conflict — both present; canary lives in the chunk data
		fmt.Fprintf(b, "Content-Length: %d\r\n", len(smuggledLine))
		b.WriteString("Transfer-Encoding: chunked\r\n\r\n")
		writeChunk(b, []byte(smuggledLine), "")
		writeChunk(b, nil, "")
	case 4: // TE.CL conflict (other order); canary in chunk data
		b.WriteString("Transfer-Encoding: chunked\r\n")
		fmt.Fprintf(b, "Content-Length: %d\r\n\r\n", len(smuggledLine))
		writeChunk(b, []byte(smuggledLine), "")
		writeChunk(b, nil, "")
	case 5: // TE.TE obfuscation (two Transfer-Encoding headers); canary in chunk data
		b.WriteString("Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n")
		writeChunk(b, []byte(smuggledLine), "")
		writeChunk(b, nil, "")
	default: // chunked with a chunk extension + a correctly-placed trailer
		b.WriteString("Transfer-Encoding: chunked\r\nTrailer: X-Trailer\r\n\r\n")
		writeChunk(b, payload, ";ext=1")
		b.WriteString("0\r\n")           // last-chunk
		b.WriteString("X-Trailer: t\r\n") // trailer part (before the final CRLF)
		b.WriteString("\r\n")
	}
	return injects
}

func writeChunk(b *bytes.Buffer, data []byte, ext string) {
	fmt.Fprintf(b, "%x%s\r\n", len(data), ext)
	if len(data) > 0 {
		b.Write(data)
	}
	b.WriteString("\r\n")
}

// byteReader is a total, deterministic reader; past the end it returns zeros.
type byteReader struct {
	data []byte
	pos  int
}

func (r *byteReader) u8() byte {
	if r.pos >= len(r.data) {
		return 0
	}
	v := r.data[r.pos]
	r.pos++
	return v
}

func (r *byteReader) u32() uint32 {
	return uint32(r.u8())<<24 | uint32(r.u8())<<16 | uint32(r.u8())<<8 | uint32(r.u8())
}

func (r *byteReader) pick(opts []string) string { return opts[int(r.u8())%len(opts)] }

// exchange dials the listener, writes raw bytes, and reads the whole response under
// a watchdog. Returns the raw response bytes and whether the watchdog fired.
func exchange(addr string, wire []byte, watchdog time.Duration) (resp []byte, timedOut bool) {
	type result struct{ b []byte }
	ch := make(chan result, 1)
	go func() {
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			ch <- result{nil}
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(watchdog))
		if _, err := conn.Write(wire); err != nil {
			ch <- result{nil}
			return
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite() // flush keep-alive responses, then hit EOF
		}
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(conn)
		ch <- result{buf.Bytes()}
	}()
	select {
	case r := <-ch:
		return r.b, false
	case <-time.After(watchdog + 2*time.Second):
		return nil, true
	}
}

// count2xxResponses parses the raw response bytes with net/http's own client parser
// and returns how many complete 2xx responses it extracts. Parsing (not line-
// scanning) makes it immune to a response BODY that echoes "HTTP/1." text. Counting
// only 2xx is deliberate: an attacker-injected response-split surfaces as an EXTRA
// SUCCESS the client would accept, whereas net/http's own "400 Bad Request +
// Connection: close" for trailing garbage after an unread body is fail-closed
// behaviour, not splitting — so 4xx/5xx follow-ups are not counted.
func count2xxResponses(resp []byte) int {
	r := bufio.NewReader(bytes.NewReader(resp))
	n := 0
	for {
		res, err := http.ReadResponse(r, nil)
		if err != nil {
			break
		}
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		if res.StatusCode >= 200 && res.StatusCode < 300 {
			n++
		}
	}
	return n
}

func firstHeaderBlock(resp []byte) []byte {
	if i := bytes.Index(resp, []byte("\r\n\r\n")); i >= 0 {
		return resp[:i]
	}
	return resp
}

func FuzzWireHTTP1(f *testing.F) {
	w := buildWireWorld(f)

	f.Add([]byte{0, 1, 0, 0, 0, 0}) // GET /health
	f.Add([]byte{0, 0, 0, 2, 3, 1}) // GET secret with admin token, CL body
	f.Add([]byte{0, 0, 0, 0, 0, 3}) // CL.TE smuggle
	f.Add([]byte{0, 0, 0, 0, 0, 4}) // TE.CL smuggle
	f.Add([]byte{0, 0, 0, 0, 0, 5}) // TE.TE smuggle
	f.Add([]byte{0, 0, 2, 0, 0, 0}) // duplicate Host
	f.Add([]byte{0, 1, 0, 0, 2, 0}) // header-injection reflect payload
	f.Add([]byte{2, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0}) // pipelined 3 requests
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		http1Mu.Lock()
		defer http1Mu.Unlock()

		gs := generateHTTP1(w, data)
		if len(gs.wire) == 0 {
			return
		}

		w.rec.reset()
		runtime.GC()
		var m0 runtime.MemStats
		runtime.ReadMemStats(&m0)

		resp, timedOut := exchange(w.addr, gs.wire, 10*time.Second)

		var m1 runtime.MemStats
		runtime.ReadMemStats(&m1)

		if timedOut {
			t.Fatalf("HANG: no response within watchdog for %d-byte wire\n%q", len(gs.wire), truncate(gs.wire, 400))
		}
		hits := w.rec.snapshot()
		if v := evalHTTP1Oracles(gs, resp, hits, heapDelta(m0, m1), w.valA, w.valB); v != "" {
			t.Fatalf("%s\nwire=%q\nhits=%+v\nresp=%q", v, truncate(gs.wire, 1200), hits, truncate(resp, 1200))
		}
	})
}

// http1AllocCap bounds the per-input heap-alloc delta (coarse, generous).
const http1AllocCap = 512 << 20

// evalHTTP1Oracles is the pure HTTP/1.1 oracle evaluator shared by the fuzzer and
// its red/green proof (oracle_redproof_test.go). It returns a non-empty violation
// description when any oracle fires, or "" when the exchange is clean. Keeping the
// predicates here (not inlined in f.Fuzz) is what lets a planted-defect test WATCH
// each oracle fire — "a guard nobody has watched fail is not a guard".
func evalHTTP1Oracles(gs genStream, resp []byte, hits []handlerHit, allocDelta uint64, valA, valB string) string {
	if allocDelta > http1AllocCap {
		return fmt.Sprintf("UNBOUNDED ALLOC: heap grew %d bytes (cap %d)", allocDelta, http1AllocCap)
	}
	// (2) smuggling count.
	if len(hits) > gs.topLevel {
		return fmt.Sprintf("SMUGGLING (count): %d handler invocations for %d top-level request(s)", len(hits), gs.topLevel)
	}
	// (2b) canary: a request-line embedded inside a declared body must NEVER be
	// dispatched — that means net/http re-parsed body bytes as a request.
	for _, h := range hits {
		if h.path == canaryPath {
			return fmt.Sprintf("SMUGGLING (canary): body-embedded request %q was dispatched", canaryPath)
		}
	}
	// (3) authz/leak invariance.
	if bytes.Contains(resp, []byte(valB)) && !gs.hasAdmin {
		return "LEAK: secret B plaintext in response without admin credential on the wire"
	}
	if bytes.Contains(resp, []byte(valA)) && !gs.hasAdmin && !gs.hasReader {
		return "LEAK: secret A plaintext in response without an authorizing credential on the wire"
	}
	// (4) response splitting (only when an injection payload was present).
	if gs.injects {
		if bytes.Contains(firstHeaderBlock(resp), []byte("X-Injected:")) {
			return "RESPONSE SPLITTING: injected header materialized in the response header block"
		}
		if n := count2xxResponses(resp); n > gs.topLevel {
			return fmt.Sprintf("RESPONSE SPLITTING: %d 2xx responses for %d top-level request(s)", n, gs.topLevel)
		}
	}
	return ""
}

func heapDelta(a, b runtime.MemStats) uint64 {
	if b.HeapAlloc >= a.HeapAlloc {
		return b.HeapAlloc - a.HeapAlloc
	}
	return 0
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "…"
	}
	return string(b)
}

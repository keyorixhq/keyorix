package wirefuzz

// FuzzWireHTTP1 feeds RAW TCP bytes to the production HTTP/1.1 parser (net/http's
// own conn reader, reached by http.Server.Serve on a loopback listener) and checks
// framing/smuggling invariants against the real router + auth + handlers.
//
// Two LANES share one driver. The STRUCTURED lane (first input byte < 0x80) turns the
// fuzz input into one to three TOP-LEVEL requests by selecting among hard-coded
// framing variants: absolute-form and authority-form request targets, Host
// mismatches, duplicate and obs-fold headers, Content-Length vs Transfer-Encoding
// combinations (CL.TE / TE.CL / TE.TE) whose bodies EMBED a hidden second request-line,
// chunk extensions and trailers, pipelined requests, oversized header sets, and
// URL-encoded CRLF payloads at points a server could reflect. Every body-length field
// is exactly right, so the smuggling count and canary oracles are sound on it. The RAW
// lane (first byte >= 0x80) lets the fuzz BYTES become framing bytes: Content-Length
// off by k and odd number forms ("+5", "005", "5, 5", raw token bytes), chunk-size
// tokens taken from the input (hex overflow, non-hex bytes), CR / bare-LF line
// terminators, whitespace before the colon, "chunked, identity" / "xchunked" TE values,
// a raw header name/value from the input, and a verbatim tail of the remaining input.
// A short CL legitimately turns the rest into a pipelined request, so the raw lane
// skips the count / canary / splitting oracles and keeps liveness, per-response leak
// and health. A fixed grammar alone would re-run the same ~33k shapes forever.
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
// DRIVER RULE: the client never half-closes before it has read the responses (see
// oracles_test.go). A FIN makes net/http cancel the request context, the auth
// middleware then fails closed with a 503 for every token-bearing request, and no
// authorized response would ever reach the leak oracle. exchange() reads responses
// until the expected count has arrived plus a short grace window for an EXTRA
// (smuggled) response, then closes.
//
// ORACLES (and, explicitly, what each does NOT verify):
//
//	(1) LIVENESS/BOUNDED — the exchange must not panic, the server must keep reading
//	    our bytes (a write that stalls past the watchdog is a HANG), and the per-input
//	    heap-allocation delta stays under a fixed cap (evalAlloc).
//	    DOES NOT verify: CPU time, goroutine/fd leaks, or allocation the GC reclaims
//	    between the two MemStats reads (the cap is coarse and generous; it catches a
//	    runaway unbounded buffer, not a modest transient). A server that simply waits
//	    for a body that never completes is NOT a hang here (it is legitimate); the
//	    post-abuse health probe catches a wedged listener.
//
//	(2) REQUEST-COUNT (smuggling), structured lane only — top-of-stack handler
//	    invocations must be <= the number of top-level requests the generator put on
//	    the wire. More means a single framed request was dispatched as several.
//	    DOES NOT verify: the converse (fewer is fine — the server may legitimately
//	    reject or close); nor does it attribute a smuggled dispatch to a wire offset.
//	    In this single-parser architecture it specifically cannot find front-end/
//	    back-end desync (there is no front end); it finds self-desync only.
//
//	(3) AUTHZ/LEAK INVARIANCE, PER REQUEST — responses arrive in request order, so the
//	    i-th response is paired with the i-th handler hit and judged against the
//	    principal THAT request presented (evalHTTP1Oracles → evalLeak): valB requires
//	    the admin principal, valA admin or the projA reader. A secret in the response to
//	    an unauthenticated request pipelined behind an admin one is therefore caught.
//	    DOES NOT verify: that every authorized request succeeds (a legitimately-rejected
//	    framing may 4xx; TestAntiVacuity_HTTP1 is what proves an authorized read is
//	    reachable), nor leaks that are not the literal seeded plaintext. It models the
//	    two seeded token strings as the only credentials.
//
//	(4) NO RESPONSE SPLITTING, structured lane only — an encoded CRLF payload emitted in
//	    a reflectable position (a ref= query value, a path segment, Origin) must never
//	    become a real header line in the first response header block, and one top-level
//	    request must never yield a second 2xx response. `injects` is set only when such
//	    a payload is actually on the wire (TestGenerator_InjectsImpliesCRLFPayload).
//	    DOES NOT verify: splitting via a body the client never reads, or via trailers;
//	    whether the server ever reflects these inputs (it currently does not echo caller
//	    headers, so this is a regression guard rather than a live finding).
//
// RED-PROOFS for each oracle are committed: oracle_redproof_test.go (predicates and
// planted-defect twins through the same driver) and anti_vacuity_test.go. The harness
// changes no production code.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
)

// http1Mu serializes per-input execution against the shared world so the recorder
// reset and the DB stay race-free under -parallel>1.
var http1Mu sync.Mutex

// genStream is a decoded byte stream plus the facts the oracles consume.
type genStream struct {
	wire     []byte
	topLevel int      // number of top-level requests emitted (smuggling reference count, structured lane)
	methods  []string // request method per top-level request, so HEAD responses parse correctly
	raw      bool     // raw lane: the count, canary and splitting oracles are off
	injects  bool     // an encoded CRLF payload is on the wire (see genOneHTTP1)
}

// crlfPayload is the encoded CRLF + header-line injection every reflectable position
// carries. Percent-encoded because a literal CRLF in a request would just be framing.
const crlfPayload = "%0d%0aX-Injected:%201"

// generateHTTP1 turns fuzz bytes into a wire stream. It is deterministic and total:
// any byte slice decodes to a valid (possibly empty) stream.
func generateHTTP1(w *wireWorld, data []byte) genStream {
	rd := &byteReader{data: data}
	b0 := rd.u8()
	gs := genStream{raw: b0&0x80 != 0, topLevel: int((b0&0x7f)%3) + 1} // 1..3 requests (pipelining when >1)
	var out bytes.Buffer
	for i := range gs.topLevel {
		if gs.raw {
			gs.methods = append(gs.methods, genRawHTTP1(w, rd, &out, i == gs.topLevel-1))
			continue
		}
		method, inj := genOneHTTP1(w, rd, &out)
		gs.methods = append(gs.methods, method)
		gs.injects = gs.injects || inj
	}
	gs.wire = out.Bytes()
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

var http1Methods = []string{"GET", "POST", "GET", "HEAD", "PUT", "DELETE"}

func genOneHTTP1(w *wireWorld, rd *byteReader, b *bytes.Buffer) (method string, injects bool) {
	start := b.Len()
	method = http1Methods[rd.u8()%6]
	var target string
	switch rd.u8() % 4 {
	case 0:
		target = "/api/v1/secrets/value?ref=" + rd.pick([]string{w.refA, w.refB, "../../etc", "proja/prod/sa",
			w.refA + crlfPayload, "proja%2Fprod%2Fsa" + crlfPayload})
	case 1:
		target = "/health"
	case 2: // absolute-form
		target = "http://127.0.0.1/api/v1/secrets/value?ref=" + rd.pick([]string{w.refA, w.refB})
	default:
		target = rd.pick([]string{"/", "/api/v1/secrets/", "//api//v1//secrets//value", "/api/v1/secrets/value", "/" + crlfPayload})
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

	switch rd.u8() % 5 {
	case 0: // obs-fold (net/http unfolds; still one request)
		b.WriteString("X-Fold: a\r\n b\r\n")
	case 1: // oversized header set (exceeds 64 KiB MaxHeaderBytes => 431/close)
		b.WriteString("X-Big: ")
		b.Write(bytes.Repeat([]byte("A"), 70<<10))
		b.WriteString("\r\n")
	case 2: // encoded CRLF payload in Origin (CORS reflection / Vary: Origin is the classic sink)
		b.WriteString("Origin: https://evil.example" + crlfPayload + "\r\n")
	case 3: // duplicate benign header (legal)
		b.WriteString("Accept: a\r\nAccept: b\r\n")
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
		b.WriteString("0\r\n")            // last-chunk
		b.WriteString("X-Trailer: t\r\n") // trailer part (before the final CRLF)
		b.WriteString("\r\n")
	}
	// `injects` is derived from what was actually emitted, so the splitting oracle can
	// never run on an input that carried no payload (nor miss one that did).
	return method, bytes.Contains(b.Bytes()[start:], []byte("%0d%0a"))
}

// genRawHTTP1 emits ONE request whose framing fields are built from fuzz bytes (the raw
// lane). Decode order is fixed (TestGenerator_RawLane* pin it): method, line
// terminator, target, credential, optional raw header, body bytes, framing kind and its
// parameters, and — on the last request only — the whole remaining input verbatim.
func genRawHTTP1(w *wireWorld, rd *byteReader, b *bytes.Buffer, last bool) (method string) {
	method = http1Methods[rd.u8()%6]
	eol := []string{"\r\n", "\r\n", "\r\n", "\n", "\r"}[rd.u8()%5] // mostly CRLF; bare LF / bare CR sometimes
	var target string
	switch rd.u8() % 4 {
	case 0:
		target = "/api/v1/secrets/value?ref=" + []string{w.refA, w.refB}[rd.u8()%2]
	case 1:
		target = "/health"
	case 2:
		target = "/api/v1/secrets/value?ref=" + w.refA + crlfPayload
	default:
		target = "/"
	}
	b.WriteString(method + " " + target + " HTTP/1.1" + eol)
	b.WriteString("Host: 127.0.0.1" + eol)
	switch rd.u8() % 4 {
	case 0:
	case 1:
		b.WriteString("Authorization: Bearer garbage-not-a-real-token" + eol)
	case 2:
		b.WriteString("Authorization: Bearer " + w.adminTok + eol)
	default:
		b.WriteString("Authorization: Bearer " + w.readTok + eol)
	}
	colon := func() string { return []string{": ", ":", " : ", ":\t"}[rd.u8()%4] }
	if rd.u8()%2 == 1 { // raw header name and value straight from the input
		name := rd.take(int(rd.u8() % 12))
		sep := colon()
		val := rd.take(int(rd.u8() % 24))
		b.Write(name)
		b.WriteString(sep)
		b.Write(val)
		b.WriteString(eol)
	}
	body := rd.take(int(rd.u8() % 48))
	// clToken renders a Content-Length value of n in one of several (mostly illegal) forms.
	clToken := func(n int) string {
		switch rd.u8() % 6 {
		case 1:
			return "+" + strconv.Itoa(n)
		case 2:
			return "00" + strconv.Itoa(n)
		case 3:
			return strconv.Itoa(n) + ", " + strconv.Itoa(n)
		case 4:
			return string(rd.take(int(rd.u8() % 10)))
		case 5:
			return "0x" + strconv.FormatInt(int64(n), 16)
		default:
			return strconv.Itoa(n)
		}
	}
	// chunked renders the chunked body with a chunk-size token taken from the input.
	chunked := func() {
		var size string
		switch rd.u8() % 4 {
		case 1: // hex digits from the input: >16 digits overflows a 64-bit chunk size
			size = fmt.Sprintf("%x", rd.take(int(rd.u8()%12)))
		case 2: // raw bytes, not necessarily hex
			size = string(rd.take(int(rd.u8() % 6)))
		case 3: // right size off by a delta
			size = fmt.Sprintf("%x", max(0, len(body)+int(int8(rd.u8()))))
		default:
			size = fmt.Sprintf("%x", len(body))
		}
		ext := []string{"", ";x=1"}[rd.u8()%2]
		b.WriteString(size + ext + eol)
		b.Write(body)
		b.WriteString(eol + "0" + eol + eol)
	}
	te := func() string {
		return []string{"chunked", "chunked, identity", "identity, chunked", "xchunked", " chunked", "Chunked", "chunked;q=1"}[rd.u8()%7]
	}
	switch rd.u8() % 6 {
	case 1: // Content-Length off by k, odd forms
		delta := int(int8(rd.u8()))
		b.WriteString("Content-Length" + colon() + clToken(max(0, len(body)+delta)) + eol + eol)
		b.Write(body)
	case 2: // chunked
		b.WriteString("Transfer-Encoding" + colon() + te() + eol + eol)
		chunked()
	case 3: // CL.TE with a wrong CL
		delta := int(int8(rd.u8()))
		b.WriteString("Content-Length" + colon() + clToken(max(0, len(body)+delta)) + eol)
		b.WriteString("Transfer-Encoding" + colon() + te() + eol + eol)
		chunked()
	case 4: // duplicate, differing Content-Length
		b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + eol)
		b.WriteString("Content-Length: " + strconv.Itoa(len(body)+1+int(rd.u8()%3)) + eol + eol)
		b.Write(body)
	case 5: // whitespace before the colon on the framing header
		b.WriteString("Transfer-Encoding : chunked" + eol + eol)
		chunked()
	default: // no framing header
		b.WriteString(eol)
	}
	if last {
		b.Write(rd.rest(4096)) // verbatim tail
	}
	return method
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

// take returns the next n input bytes (zero-padded past the end, like u8).
func (r *byteReader) take(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = r.u8()
	}
	return out
}

// rest returns up to limit of the unread input and consumes it.
func (r *byteReader) rest(limit int) []byte {
	if r.pos >= len(r.data) {
		return nil
	}
	out := r.data[r.pos:]
	if len(out) > limit {
		out = out[:limit]
	}
	r.pos = len(r.data)
	return out
}

// h1Resp is one HTTP/1.1 response parsed from the raw bytes the server returned.
type h1Resp struct {
	status   int
	text     []byte // header fields + body: what the leak oracle scans
	complete bool   // false when the body was truncated or this is an unparsed tail
}

// parseHTTP1Responses parses the raw response bytes with net/http's own client parser,
// one response per request in order (methods[i] is request i's method, so a HEAD
// response is not mistaken for one with a body). Any unparsed tail is returned as a
// final element with status 0 so a secret hidden there is still scanned, unattributed.
func parseHTTP1Responses(resp []byte, methods []string) []h1Resp {
	rdr := bytes.NewReader(resp)
	br := bufio.NewReader(rdr)
	var out []h1Resp
	consumed := 0
	for i := 0; ; i++ {
		method := http.MethodGet
		if i < len(methods) {
			method = methods[i]
		}
		res, err := http.ReadResponse(br, &http.Request{Method: method})
		if err != nil {
			break
		}
		var t bytes.Buffer
		_ = res.Header.Write(&t)
		_, cerr := io.Copy(&t, res.Body)
		_ = res.Body.Close()
		out = append(out, h1Resp{status: res.StatusCode, text: t.Bytes(), complete: cerr == nil})
		if cerr != nil {
			consumed = len(resp) // the truncated body absorbed the rest
			break
		}
		consumed = len(resp) - rdr.Len() - br.Buffered()
	}
	if consumed < len(resp) {
		out = append(out, h1Resp{text: resp[consumed:]})
	}
	return out
}

func countComplete(rs []h1Resp) int {
	n := 0
	for _, r := range rs {
		if r.complete {
			n++
		}
	}
	return n
}

const (
	// h1IdleWait is how long exchange waits for the next response while fewer than the
	// expected number have arrived (a server may legitimately be waiting for more body).
	h1IdleWait = 2 * time.Second
	// h1GraceWait is how long it keeps listening after the expected count arrived, to
	// see an EXTRA response (a smuggled dispatch) before closing.
	h1GraceWait = 300 * time.Millisecond
)

// exchange dials the listener, writes raw bytes WITHOUT half-closing, and reads the
// responses: until expect complete ones have arrived plus a short grace window, EOF,
// or an idle wait with fewer than expect. timedOut reports a HANG: the server stopped
// reading our bytes (the write stalled past the watchdog) or the exchange could not
// finish at all. A server that merely waits for a body that never completes is not a
// hang (it is legitimate); the post-abuse health probe catches a wedged listener.
func exchange(addr string, wire []byte, methods []string, expect int, watchdog time.Duration) (resp []byte, timedOut bool) {
	type result struct {
		b       []byte
		stalled bool
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			ch <- result{}
			return
		}
		defer func() { _ = conn.Close() }()
		hard := time.Now().Add(watchdog)
		_ = conn.SetDeadline(hard)
		stalled := false
		if _, err := conn.Write(wire); err != nil {
			// A reset/closed pipe (e.g. 431 then close while we still write) is normal:
			// keep reading what the server sent. A write TIMEOUT means it stopped reading.
			var ne net.Error
			stalled = errors.As(err, &ne) && ne.Timeout()
		}
		var buf bytes.Buffer
		chunk := make([]byte, 32<<10)
		for !stalled {
			wait := h1IdleWait
			if countComplete(parseHTTP1Responses(buf.Bytes(), methods)) >= expect {
				wait = h1GraceWait
			}
			dl := time.Now().Add(wait)
			if dl.After(hard) {
				dl = hard
			}
			_ = conn.SetReadDeadline(dl)
			n, err := conn.Read(chunk)
			buf.Write(chunk[:n])
			if err != nil {
				break
			}
		}
		ch <- result{buf.Bytes(), stalled}
	}()
	select {
	case r := <-ch:
		return r.b, r.stalled
	case <-time.After(watchdog + 2*time.Second):
		return nil, true
	}
}

func firstHeaderBlock(resp []byte) []byte {
	if head, _, found := bytes.Cut(resp, []byte("\r\n\r\n")); found {
		return head
	}
	return resp
}

func FuzzWireHTTP1(f *testing.F) {
	w := buildWireWorld(f)

	f.Add([]byte{0, 0, 1, 0, 0, 0, 0})                            // GET /health
	f.Add([]byte{0, 0, 0, 0, 0, 2, 4, 0})                         // admin GET secret A (authorized read)
	f.Add([]byte{0, 0, 0, 1, 0, 3, 4, 0})                         // reader GET secret B (must be denied)
	f.Add([]byte{0, 0, 0, 2, 3, 1})                               // GET secret with admin token, CL body
	f.Add([]byte{0, 0, 0, 0, 0, 3})                               // CL.TE smuggle
	f.Add([]byte{0, 0, 0, 0, 0, 4})                               // TE.CL smuggle
	f.Add([]byte{0, 0, 0, 0, 0, 5})                               // TE.TE smuggle
	f.Add([]byte{0, 0, 2, 0, 0, 0})                               // duplicate Host
	f.Add([]byte{0, 0, 1, 0, 0, 2, 0})                            // header-injection payload in Origin
	f.Add([]byte{0, 0, 0, 4, 0, 0, 4, 0})                         // header-injection payload in the ref= query value
	f.Add([]byte{2, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0}) // pipelined 3 requests
	f.Add(rawSeedShortCL())                                       // raw lane: Content-Length = len(body)-3
	f.Add(rawSeedChunkOverflow())                                 // raw lane: 22-hex-digit chunk size
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		http1Mu.Lock()
		defer http1Mu.Unlock()

		gs := generateHTTP1(w, data)
		if len(gs.wire) == 0 {
			return
		}

		w.rec.reset()
		var resp []byte
		var timedOut bool
		delta := measureAlloc(func() { resp, timedOut = exchange(w.addr, gs.wire, gs.methods, gs.topLevel, 10*time.Second) })

		if timedOut {
			t.Fatalf("HANG: server stopped reading within watchdog for %d-byte wire\n%q", len(gs.wire), truncate(gs.wire, 400))
		}
		hits := w.rec.snapshot()
		if v := evalHTTP1Oracles(gs, resp, hits, delta, w.valA, w.valB); v != "" {
			t.Fatalf("%s\nwire=%q\nhits=%+v\nresp=%q", v, truncate(gs.wire, 1200), hits, truncate(resp, 1200))
		}
		// (5) POST-ABUSE HEALTH — the abusive input must not break the listener for a
		// later clean client on a FRESH connection (closes the single-connection gap).
		if err := httpHealthProbe(w.addr); err != nil {
			t.Fatalf("POST-ABUSE HEALTH: server did not serve a later clean /health after %d-byte wire: %v\nwire=%q",
				len(gs.wire), err, truncate(gs.wire, 800))
		}
	})
}

// rawSeedShortCL is a raw-lane input whose Content-Length is 3 less than the body
// (8 bytes, CL=5), the shape that desyncs a framer when the body is longer than declared.
func rawSeedShortCL() []byte {
	s := []byte{0x80, 0, 0, 1, 0, 0, 8} // raw, GET, CRLF, /health, no cred, no raw header, 8 body bytes
	s = append(s, []byte("BODYBODY")...)
	return append(s, 1, 0xFD, 0) // framing kind 1 (CL), delta -3, plain token
}

// rawSeedChunkOverflow is a raw-lane input with a chunk-size token of 22 hex digits
// (overflows a 64-bit size): framing kind 2, plain TE, size mode 1, 11 input bytes.
func rawSeedChunkOverflow() []byte {
	s := []byte{0x80, 1, 0, 1, 0, 0, 4} // raw, POST, CRLF, /health, no cred, no raw header, 4 body bytes
	s = append(s, []byte("abcd")...)
	s = append(s, 2, 0, 0, 1, 11) // kind 2, colon ": ", TE "chunked", size mode 1, 11 input bytes
	s = append(s, bytes.Repeat([]byte{0xFF}, 11)...)
	return append(s, 0)
}

// evalHTTP1Oracles is the pure HTTP/1.1 oracle evaluator shared by the fuzzer and
// its red/green proof (oracle_redproof_test.go). It returns a non-empty violation
// description when any oracle fires, or "" when the exchange is clean. Keeping the
// predicates here (not inlined in f.Fuzz) is what lets a planted-defect test WATCH
// each oracle fire — "a guard nobody has watched fail is not a guard".
func evalHTTP1Oracles(gs genStream, resp []byte, hits []handlerHit, allocDelta uint64, valA, valB string) string {
	if v := evalAlloc(allocDelta); v != "" {
		return v
	}
	if !gs.raw {
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
	}
	// (3) authz/leak invariance, PER REQUEST: the i-th response belongs to the i-th
	// handler hit (one connection answers in order), so judge it against the principal
	// that request presented. A response with no hit (server-generated, or a smuggled
	// tail) has no credential at all.
	resps := parseHTTP1Responses(resp, gs.methods)
	for i, r := range resps {
		var cred credsSent
		if i < len(hits) {
			cred = credFromPrincipal(hits[i].principal)
		}
		if v := evalLeak(r.text, cred, valA, valB); v != "" {
			return fmt.Sprintf("%s [response %d of %d]", v, i+1, len(resps))
		}
	}
	// (4) response splitting (only when an injection payload was on the wire).
	if gs.injects && !gs.raw {
		if bytes.Contains(firstHeaderBlock(resp), []byte("X-Injected:")) {
			return "RESPONSE SPLITTING: injected header materialized in the response header block"
		}
		n2xx := 0
		for _, r := range resps {
			if r.status >= 200 && r.status < 300 {
				n2xx++
			}
		}
		if n2xx > gs.topLevel {
			return fmt.Sprintf("RESPONSE SPLITTING: %d 2xx responses for %d top-level request(s)", n2xx, gs.topLevel)
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

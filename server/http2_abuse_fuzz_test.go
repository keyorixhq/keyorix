package main

// FuzzHTTP2AbusiveFrames establishes a real HTTP/2-over-ALPN connection to a
// real HTTPS listener (newHTTPServer + the hardened createTLSConfig; net/http's
// auto-h2) and throws fuzz-chosen sequences of abusive HTTP/2 frames at it —
// rapid stream open+reset, SETTINGS floods, PING floods, oversized HEADER
// blocks (HEADERS + CONTINUATION, above the advertised header-list limit),
// CONTINUATION floods, stray WINDOW_UPDATE/DATA/GOAWAY — then checks the server
// as a whole is still responsive to a normal request on an independent
// connection.
//
// Oracles:
//   - no panic: net/http and x/net/http2 recover a panic on a connection or
//     handler goroutine, log "http: panic serving" / "http2: panic serving" to
//     http.Server.ErrorLog and reset/close the connection, so a panic does NOT
//     crash the process. The harness installs a panicLog as ErrorLog and fails
//     the input if it recorded one, checked after the abusive connection and
//     again after the healthy ping. Proven able to fire by
//     TestHTTP2AbuseHarness_DetectsServerPanic.
//   - server stays responsive: after each abusive sequence, an independent,
//     well-behaved HTTP/2 client must get a 204 from the server within a short
//     deadline. A connection-level DoS that wedged the whole server (goroutine
//     exhaustion, a global lock held, a crash-loop) would fail here.
//   - bounded goroutines: once, after the whole corpus, the live goroutine count
//     must be under a coarse ceiling. This is a backstop for a gross
//     per-connection leak only; it is not checked per input and was not
//     red-proofed.
//
// The abuse ops really reach the limits they are named for:
// TestHTTP2AbuseOps_ReachTheirLimit asserts that every program byte selecting
// the oversized-header op decodes to a header list above the server's advertised
// SETTINGS_MAX_HEADER_LIST_SIZE (and that the live server then does not answer
// it with a 204), and that the CONTINUATION op sends floods of up to ~1,000
// frames.
//
// Which limits are whose: the HTTP listener's HTTP/2 protections here are
// STANDARD LIBRARY defaults (net/http auto-configures http2.Server: default
// MaxConcurrentStreams 250, SETTINGS_MAX_HEADER_LIST_SIZE derived from
// http.Server.MaxHeaderBytes = 64 KiB, plus the Go runtime's CVE-2023-39325
// rapid-reset mitigation). Keyorix does NOT set per-connection HTTP/2 limits on
// the REST listener itself (it sets the connection-level Read/Write/Idle timeouts
// and MaxHeaderBytes in newHTTPServer, which this harness uses; the h2 frame
// limits come from the Go version). The gRPC listener's h2 limits
// (MaxConcurrentStreams 128, MaxHeaderListSize 64 KiB) ARE Keyorix-set — see the
// gRPC abuse test and server/grpc/connection_limits_test.go.
//
// What this does NOT verify: it does not measure heap bytes directly (goroutine
// count + server responsiveness are the proxies); it does not assert a specific
// numeric cap on streams/headers (that is the stdlib's, pinned by the gRPC
// SETTINGS test for the gRPC side); and it uses a trivial handler, so it exercises
// the transport/framing layer, not application handlers.

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// h2AbuseMaxFrame is the default SETTINGS_MAX_FRAME_SIZE (RFC 9113 §6.5.2);
// header blocks are split into HEADERS+CONTINUATION frames no larger than this,
// otherwise the server answers FRAME_SIZE_ERROR instead of exercising the
// header-list limit.
const h2AbuseMaxFrame = 16 << 10

// h2Harness is a loopback HTTPS (h2) listener built with newHTTPServer and the
// hardened tls.Config, a panicLog on its ErrorLog, and an independent healthy
// client.
type h2Harness struct {
	addr   string
	panics *panicLog
	client *http.Client
}

func startH2Harness(tb testing.TB, handler http.Handler) *h2Harness {
	tb.Helper()
	certFile, keyFile := writeSelfSignedCert(tb, tb.TempDir())

	cfg := &config.Config{}
	cfg.Server.HTTP.TLS.Enabled = true
	cfg.Server.HTTP.TLS.CertFile = certFile
	cfg.Server.HTTP.TLS.KeyFile = keyFile
	tlsConfig, err := createTLSConfig(cfg)
	if err != nil {
		tb.Fatalf("createTLSConfig: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	h := &h2Harness{addr: ln.Addr().String(), panics: newPanicLog()}

	srv := newHTTPServer(h.addr, handler)
	srv.TLSConfig = tlsConfig
	srv.ErrorLog = h.panics.logger()
	go srv.ServeTLS(ln, "", "") //nolint:errcheck
	tb.Cleanup(func() { _ = srv.Close() })

	// An independent, well-behaved HTTP/2 client used to prove server-wide
	// responsiveness after each abusive sequence.
	h.client = &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}, // #nosec G402 -- loopback self-signed test cert
		},
		Timeout: 5 * time.Second,
	}
	tb.Cleanup(h.client.CloseIdleConnections)
	return h
}

// run replays program on an abusive connection and returns an error if the
// server panicked or is no longer responsive to a normal request.
func (h *h2Harness) run(program []byte) error {
	// Abuse errors are swallowed: a server that rejects abuse by resetting or
	// closing the connection is the desired behaviour; the oracles below judge.
	_, _ = abuseConnection(h.addr, program, 0)
	if err := h.panics.err(); err != nil {
		return err
	}

	if err := pingHealthy(h.client, h.addr); err != nil {
		// x/net/http2 queues the RST for a panicking handler before it logs.
		if perr := h.panics.waitErr(time.Second); perr != nil {
			return perr
		}
		return fmt.Errorf("server unresponsive after abusive frames: %w", err)
	}
	return h.panics.err()
}

func FuzzHTTP2AbusiveFrames(f *testing.F) {
	h := startH2Harness(f, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	// Confirm the baseline works before fuzzing, so a later failure means the
	// abuse broke it, not that it never worked.
	if err := pingHealthy(h.client, h.addr); err != nil {
		f.Fatalf("baseline healthy request failed before any abuse: %v", err)
	}

	baseGoroutines := runtime.NumGoroutine()

	f.Add([]byte{0x00, 0x00, 0x00})       // settings flood
	f.Add([]byte{0x20, 0x30, 0x20, 0x30}) // open+reset rapid reset
	f.Add([]byte{0x10, 0x10, 0x10})       // oversized headers
	f.Add([]byte{0x4f, 0x40, 0x40})       // continuation flood (op 4)
	f.Add([]byte{0x30, 0x30, 0x30})       // ping flood (op 3)
	f.Add([]byte{0x50, 0x60, 0x70, 0x80}) // window / data / goaway / settings

	f.Fuzz(func(t *testing.T, program []byte) {
		if err := h.run(program); err != nil {
			t.Fatal(err)
		}
	})

	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseGoroutines+64 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if g := runtime.NumGoroutine(); g > baseGoroutines+64 {
		f.Fatalf("goroutine leak: %d now vs %d baseline (ceiling +64)", g, baseGoroutines)
	}
}

// pingHealthy issues one normal HTTP/2 GET and requires the 204 the handler
// returns.
func pingHealthy(c *http.Client, addr string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/", nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close() //nolint:errcheck
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		return &abuseErr{resp.StatusCode}
	}
	return nil
}

type abuseErr struct{ code int }

func (e *abuseErr) Error() string { return "unexpected status code: " + http.StatusText(e.code) }

// abuseResult is what the server sent back on the abusive connection.
type abuseResult struct {
	statuses []string // :status of every response HEADERS frame
	rst      bool     // saw RST_STREAM
	goaway   bool     // saw GOAWAY
	closed   bool     // the server closed the connection
}

func (r abuseResult) sawStatus(s string) bool {
	return slices.Contains(r.statuses, s)
}

func (r abuseResult) reacted() bool {
	return len(r.statuses) > 0 || r.rst || r.goaway || r.closed
}

// abuseConnection opens one raw TLS+h2 connection and replays the fuzz program as
// a sequence of abusive HTTP/2 frames. Write errors end the replay quietly: a
// server that rejects abuse by resetting/closing the connection is the desired
// behaviour, and the oracles (not this function) judge the server. After the
// program it waits up to wait (0 = not at all) for the server's first reaction
// (a response, RST_STREAM, GOAWAY or close) and reports what it saw.
func abuseConnection(addr string, program []byte, wait time.Duration) (abuseResult, error) {
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}) // #nosec G402 -- loopback self-signed test cert
	if err != nil {
		return abuseResult{}, err
	}
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(4*time.Second + wait))

	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		return abuseResult{}, err
	}
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	if err := fr.WriteSettings(); err != nil {
		return abuseResult{}, err
	}

	// Drain the server's frames concurrently so its writes never block us, and
	// record what it says.
	var (
		mu   sync.Mutex
		res  abuseResult
		sig  = make(chan struct{}, 1)
		done = make(chan struct{})
	)
	notify := func() {
		select {
		case sig <- struct{}{}:
		default:
		}
	}
	go func() {
		defer close(done)
		for {
			fm, err := fr.ReadFrame()
			if err != nil {
				return
			}
			reaction := true
			mu.Lock()
			switch v := fm.(type) {
			case *http2.MetaHeadersFrame:
				res.statuses = append(res.statuses, v.PseudoValue("status"))
			case *http2.RSTStreamFrame:
				res.rst = true
			case *http2.GoAwayFrame:
				res.goaway = true
			default:
				reaction = false // the server's own SETTINGS/ACK/PING are not a reaction
			}
			mu.Unlock()
			if reaction {
				notify()
			}
		}
	}()
	defer func() { _ = conn.Close(); <-done }()

	replayAbuse(fr, program)

	if wait > 0 {
		select {
		case <-sig:
		case <-done:
		case <-time.After(wait):
		}
	}
	mu.Lock()
	out := res
	mu.Unlock()
	select {
	case <-done:
		out.closed = true
	default:
	}
	return out, nil
}

// replayAbuse writes the abusive frame sequence for program on fr.
func replayAbuse(fr *http2.Framer, program []byte) {
	streamID := uint32(1)
	nextStream := func() uint32 {
		id := streamID
		streamID += 2
		return id
	}

	// Cap the number of operations so one input cannot run unbounded.
	const maxOps = 512
	n := min(len(program), maxOps)
	for i := range n {
		b := program[i]
		op := b >> 4
		var werr error
		switch op % 8 {
		case 0: // SETTINGS flood
			werr = fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: uint32(b) << 8})
		case 1: // oversized HEADER block: HEADERS + CONTINUATIONs above the header-list limit
			werr = writeHeaderFragments(fr, nextStream(), bigHeaderFragments(b))
		case 2: // rapid reset: open a stream then immediately reset it
			id := nextStream()
			if werr = writeHeaders(fr, id, smallHeaderBlock(), true); werr == nil {
				werr = fr.WriteRSTStream(id, http2.ErrCodeCancel)
			}
		case 3: // PING flood
			var p [8]byte
			p[0] = b
			werr = fr.WritePing(false, p)
		case 4: // CONTINUATION flood: HEADERS without END_HEADERS, then many empty CONTINUATIONs
			id := nextStream()
			if werr = writeHeaders(fr, id, smallHeaderBlock(), false); werr == nil {
				for j := 0; j < continuationFloodCount(b) && werr == nil; j++ {
					werr = fr.WriteContinuation(id, false, nil)
				}
			}
		case 5: // stray WINDOW_UPDATE
			werr = fr.WriteWindowUpdate(0, uint32(b)<<16)
		case 6: // stray DATA on a maybe-unopened stream
			werr = fr.WriteData(nextStream(), false, []byte("abuse"))
		case 7: // GOAWAY from the client
			werr = fr.WriteGoAway(streamID, http2.ErrCodeNo, nil)
		}
		if werr != nil {
			return // server closed/reset: fine
		}
	}
}

// continuationFloodCount is how many CONTINUATION frames op 4 sends after its
// HEADERS: 1 to 961, selected by the low nibble of the program byte.
func continuationFloodCount(b byte) int { return 1 + int(b&0x0f)*64 }

// writeHeaders writes a HEADERS frame carrying an already-encoded header block.
func writeHeaders(fr *http2.Framer, id uint32, block []byte, endHeaders bool) error {
	return fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      id,
		BlockFragment: block,
		EndStream:     true,
		EndHeaders:    endHeaders,
	})
}

func smallHeaderBlock() []byte {
	var buf []byte
	enc := hpack.NewEncoder(bufWriter(&buf))
	_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: "localhost"})
	return buf
}

// bigHeaderFragments builds a header block whose decoded size exceeds the
// server's advertised SETTINGS_MAX_HEADER_LIST_SIZE (MaxHeaderBytes + 4096 =
// 69,632) for EVERY program byte: 72 to 132 fields of ~1,063 decoded bytes
// each (>= 76 KB). The fields are never-indexed (Sensitive) so the wire block
// is large too rather than collapsing to HPACK index references, and the block
// is split into fragments of at most h2AbuseMaxFrame bytes (one HEADERS plus
// CONTINUATION frames).
func bigHeaderFragments(b byte) [][]byte {
	var buf []byte
	enc := hpack.NewEncoder(bufWriter(&buf))
	_ = enc.WriteField(hpack.HeaderField{Name: ":method", Value: "GET"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":path", Value: "/"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	_ = enc.WriteField(hpack.HeaderField{Name: ":authority", Value: "localhost"})
	val := make([]byte, 1024)
	for i := range val {
		val[i] = 'a'
	}
	count := 72 + int(b&0x0f)*4
	for range count {
		_ = enc.WriteField(hpack.HeaderField{Name: "x-abuse", Value: string(val), Sensitive: true})
	}

	var frags [][]byte
	for len(buf) > h2AbuseMaxFrame {
		frags = append(frags, buf[:h2AbuseMaxFrame])
		buf = buf[h2AbuseMaxFrame:]
	}
	return append(frags, buf)
}

// writeHeaderFragments writes frags as one HEADERS frame (END_STREAM) followed by
// CONTINUATION frames; END_HEADERS is set on the last.
func writeHeaderFragments(fr *http2.Framer, id uint32, frags [][]byte) error {
	if err := writeHeaders(fr, id, frags[0], len(frags) == 1); err != nil {
		return err
	}
	for i, frag := range frags[1:] {
		if err := fr.WriteContinuation(id, i == len(frags)-2, frag); err != nil {
			return err
		}
	}
	return nil
}

// bufWriter adapts a []byte pointer to io.Writer for the hpack encoder.
func bufWriter(p *[]byte) io.Writer { return (*byteSliceWriter)(p) }

type byteSliceWriter []byte

func (w *byteSliceWriter) Write(b []byte) (int, error) {
	*w = append(*w, b...)
	return len(b), nil
}

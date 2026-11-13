package main

// FuzzHTTP2AbusiveFrames establishes a real HTTP/2-over-ALPN connection to the
// real hardened HTTPS listener (createTLSConfig + net/http's auto-h2) and throws
// fuzz-chosen sequences of abusive HTTP/2 frames at it — rapid stream open+reset,
// SETTINGS floods, PING floods, oversized HEADER blocks, CONTINUATION floods,
// stray WINDOW_UPDATE/DATA/GOAWAY — then checks the server as a whole is still
// responsive to a normal request on an independent connection.
//
// Oracles:
//   - no panic: a server-side panic crashes the test process and fails the fuzz.
//   - server stays responsive: after each abusive sequence, an independent,
//     well-behaved HTTP/2 client must get a 204 from the server within a short
//     deadline. A connection-level DoS that wedged the whole server (goroutine
//     exhaustion, a global lock held, a crash-loop) would fail here.
//   - bounded goroutines: the live goroutine count must return under a ceiling
//     after the corpus, catching a per-connection goroutine leak.
//
// Which limits are whose: the HTTP listener's HTTP/2 protections here are
// STANDARD LIBRARY defaults (net/http auto-configures http2.Server: default
// MaxConcurrentStreams 250, SETTINGS_MAX_HEADER_LIST_SIZE derived from
// http.Server.MaxHeaderBytes = 64 KiB, plus the Go runtime's CVE-2023-39325
// rapid-reset mitigation). Keyorix does NOT set per-connection HTTP/2 limits on
// the REST listener itself (it sets the connection-level Read/Write/Idle timeouts
// and MaxHeaderBytes in newHTTPServer; the h2 frame limits come from the Go
// version). The gRPC listener's h2 limits (MaxConcurrentStreams 128,
// MaxHeaderListSize 64 KiB) ARE Keyorix-set — see the gRPC abuse test and
// server/grpc/connection_limits_test.go.
//
// What this does NOT verify: it does not measure heap bytes directly (goroutine
// count + server responsiveness are the proxies); it does not assert a specific
// numeric cap on streams/headers (that is the stdlib's, pinned by the gRPC
// SETTINGS test for the gRPC side); and it uses a trivial handler, so it exercises
// the transport/framing layer, not application handlers.

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func FuzzHTTP2AbusiveFrames(f *testing.F) {
	dir := f.TempDir()
	certFile, keyFile := writeSelfSignedCert(f, dir)

	cfg := &config.Config{}
	cfg.Server.HTTP.TLS.Enabled = true
	cfg.Server.HTTP.TLS.CertFile = certFile
	cfg.Server.HTTP.TLS.KeyFile = keyFile

	tlsConfig, err := createTLSConfig(cfg)
	if err != nil {
		f.Fatalf("createTLSConfig: %v", err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		f.Fatalf("listen: %v", err)
	}
	defer ln.Close() //nolint:errcheck

	srv := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	go srv.ServeTLS(ln, "", "") //nolint:errcheck
	f.Cleanup(func() { _ = srv.Close() })
	addr := ln.Addr().String()

	// An independent, well-behaved HTTP/2 client used to prove server-wide
	// responsiveness after each abusive sequence.
	healthyClient := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}, // #nosec G402 -- loopback self-signed test cert
		},
		Timeout: 5 * time.Second,
	}
	defer healthyClient.CloseIdleConnections()

	// Confirm the baseline works before fuzzing, so a later failure means the
	// abuse broke it, not that it never worked.
	if err := pingHealthy(healthyClient, addr); err != nil {
		f.Fatalf("baseline healthy request failed before any abuse: %v", err)
	}

	baseGoroutines := runtime.NumGoroutine()

	f.Add([]byte{0x00, 0x00, 0x00})       // settings flood
	f.Add([]byte{0x20, 0x30, 0x20, 0x30}) // open+reset rapid reset
	f.Add([]byte{0x10, 0x10, 0x10})       // oversized headers
	f.Add([]byte{0x40, 0x40, 0x40})       // ping flood
	f.Add([]byte{0x50, 0x60, 0x70, 0x80}) // continuation / window / data / goaway

	f.Fuzz(func(t *testing.T, program []byte) {
		abuseConnection(addr, program)

		// Oracle: the server stays responsive on an independent connection.
		if err := pingHealthy(healthyClient, addr); err != nil {
			t.Fatalf("server unresponsive after abusive frames: %v", err)
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

// abuseConnection opens one raw TLS+h2 connection and replays the fuzz program as
// a sequence of abusive HTTP/2 frames. All errors are swallowed: a server that
// rejects abuse by resetting/closing the connection is the desired behaviour, and
// the responsiveness oracle (not this function) is what judges the server.
func abuseConnection(addr string, program []byte) {
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}) // #nosec G402 -- loopback self-signed test cert
	if err != nil {
		return
	}
	defer conn.Close() //nolint:errcheck
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))

	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		return
	}
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		return
	}

	// Drain the server's frames concurrently so its writes never block us.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, err := fr.ReadFrame(); err != nil {
				return
			}
		}
	}()
	defer func() { _ = conn.Close(); <-done }()

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
		op := program[i] >> 4
		var werr error
		switch op % 8 {
		case 0: // SETTINGS flood
			werr = fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: uint32(program[i]) << 8})
		case 1: // oversized HEADER block
			werr = writeHeaders(fr, nextStream(), bigHeaderBlock(1+int(program[i])), true)
		case 2: // rapid reset: open a stream then immediately reset it
			id := nextStream()
			if werr = writeHeaders(fr, id, smallHeaderBlock(), true); werr == nil {
				werr = fr.WriteRSTStream(id, http2.ErrCodeCancel)
			}
		case 3: // PING flood
			var p [8]byte
			p[0] = program[i]
			werr = fr.WritePing(false, p)
		case 4: // CONTINUATION flood: HEADERS without END_HEADERS, then CONTINUATIONs
			id := nextStream()
			if werr = writeHeaders(fr, id, smallHeaderBlock(), false); werr == nil {
				for j := 0; j < 4 && werr == nil; j++ {
					werr = fr.WriteContinuation(id, false, smallHeaderBlock())
				}
			}
		case 5: // stray WINDOW_UPDATE
			werr = fr.WriteWindowUpdate(0, uint32(program[i])<<16)
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

// bigHeaderBlock builds a header block with many large header fields, intended to
// exceed SETTINGS_MAX_HEADER_LIST_SIZE.
func bigHeaderBlock(extra int) []byte {
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
	count := 4 + extra%64
	for range count {
		_ = enc.WriteField(hpack.HeaderField{Name: "x-abuse", Value: string(val)})
	}
	return buf
}

// bufWriter adapts a []byte pointer to io.Writer for the hpack encoder.
func bufWriter(p *[]byte) io.Writer { return (*byteSliceWriter)(p) }

type byteSliceWriter []byte

func (w *byteSliceWriter) Write(b []byte) (int, error) {
	*w = append(*w, b...)
	return len(b), nil
}

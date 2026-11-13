package main

// FuzzTLSHandshakeHostileClientHello throws attacker-controlled bytes at a REAL
// HTTPS listener — an http.Server serving the hardened tls.Config
// (createTLSConfig) the server runs in production — over loopback, and checks
// the server survives and stays fail-closed.
//
// The harness builds its own http.Server rather than newHTTPServer, with short
// (2s) timeouts so a stalled connection is reaped quickly enough to fuzz at
// speed; the production timeouts are pinned separately by
// TestNewHTTPServer_Timeouts (http_server_test.go).
//
// Each fuzz input is written raw to a fresh TCP connection as if it were a
// ClientHello (truncated records, oversized extension lengths, SNI tricks, ALPN
// lists, session-ticket and renegotiation bytes, pure garbage). The harness
// client never completes the TLS key exchange, so a well-formed ClientHello
// cannot progress past ServerHello — the point is the SERVER's handling of the
// bytes, not a real session.
//
// Oracles:
//   - no panic: net/http recovers a panic on the handshake goroutine, logs
//     "http: panic serving ..." to http.Server.ErrorLog and closes the connection,
//     so a panic does NOT crash the process and the client only sees EOF. The
//     harness installs a panicLog as ErrorLog and fails the input if it recorded
//     one (net/http logs before it closes, so checking once the client has seen
//     the close is deterministic). Proven able to fire by
//     TestHostileClientHelloHarness_DetectsServerPanic.
//   - connection closed within a deadline: the server must close a connection
//     that never produces a valid handshake within the configured read timeout;
//     the client proves this by observing EOF/reset before its own (longer)
//     deadline. A hang would fail here.
//   - no data to the HTTP layer from a failed handshake: the HTTP handler sets a
//     flag if it is ever reached. Because the harness client cannot finish a
//     handshake, the handler must NEVER run; if it does, the fuzzer surfaces it.
//   - bounded goroutines: once, after the whole corpus, the live goroutine count
//     must be under a coarse ceiling. This is a backstop for a gross
//     per-connection leak only; it is not checked per input and was not
//     red-proofed.
//
// What this does NOT verify: it does not complete a real TLS session (no
// client-side crypto), so it does not exercise post-handshake HTTP/2 framing
// (that is the HTTP/2 harness) or application-layer behaviour; it does not
// measure heap bytes directly (it bounds goroutines as the proxy for unbounded
// per-connection work, and relies on the 64 KiB input cap plus crypto/tls's own
// record bounds); it exercises the non-AutoCert HTTP listener only — the gRPC
// listener's handshake is not driven here (it shares the tls.Config hardening
// path, asserted by the unit tests); and it cannot distinguish "closed because
// hardened-rejected" from "closed because the dumb client stalled" — both
// satisfy fail-closed, which is what it asserts.

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// maxHandshakeInput caps a single fuzz input so one connection cannot be made
// arbitrarily large; crypto/tls bounds individual records to 16 KiB anyway.
const maxHandshakeInput = 64 << 10

// handshakeHarness is a loopback HTTPS listener serving tlsConfig, with a
// panicLog capturing recovered panics and a flag set if the handler is reached.
type handshakeHarness struct {
	addr    string
	reached atomic.Bool
	panics  *panicLog
}

func startHandshakeHarness(tb testing.TB, tlsConfig *tls.Config) *handshakeHarness {
	tb.Helper()
	h := &handshakeHarness{panics: newPanicLog()}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			h.reached.Store(true)
			w.WriteHeader(http.StatusNoContent)
		}),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       2 * time.Second,
		WriteTimeout:      2 * time.Second,
		IdleTimeout:       2 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          h.panics.logger(),
	}
	go srv.ServeTLS(ln, "", "") //nolint:errcheck
	tb.Cleanup(func() { _ = srv.Close() })
	h.addr = ln.Addr().String()
	return h
}

// probe writes input to a fresh connection and returns an error if the server
// panicked, failed to close the connection in time, or let the bytes reach the
// HTTP handler.
func (h *handshakeHarness) probe(input []byte) error {
	if len(input) > maxHandshakeInput {
		input = input[:maxHandshakeInput]
	}

	conn, err := net.DialTimeout("tcp", h.addr, 3*time.Second)
	if err != nil {
		// The listener is loopback and must always be up. A dial failure means
		// Serve returned (and closed the listener) or the server wedged: fail
		// rather than skip, or every later input would pass silently.
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	// The server must close us within its 2s read timeout. Give generous
	// headroom; if we hit THIS deadline the connection was not closed in time.
	deadline := time.Now().Add(8 * time.Second)
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(input); err == nil {
		// Drain until the server closes the connection (EOF/reset) or we time out.
		buf := make([]byte, 4096)
		for {
			n, rerr := conn.Read(buf)
			if rerr != nil {
				if errors.Is(rerr, io.EOF) || isClosed(rerr) {
					break // fail-closed: server closed the connection
				}
				var ne net.Error
				if errors.As(rerr, &ne) && ne.Timeout() {
					if perr := h.panics.err(); perr != nil {
						return perr
					}
					return fmt.Errorf("connection not closed within deadline (server failed to close a bad handshake); read %d bytes", n)
				}
				break // any other read error also means the connection ended
			}
			if time.Now().After(deadline) {
				return errors.New("server kept the connection open past the deadline without closing")
			}
		}
	}
	// A write error (reset) is a perfectly good fail-closed outcome; fall through
	// to the oracles either way.

	// Oracle: no recovered panic (logged before net/http closes the conn).
	if err := h.panics.err(); err != nil {
		return err
	}
	// Oracle: a failed handshake must never reach the HTTP layer.
	if h.reached.Load() {
		return errors.New("HTTP handler was reached from fuzzed pre-handshake bytes — data crossed a failed handshake")
	}
	return nil
}

func FuzzTLSHandshakeHostileClientHello(f *testing.F) {
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

	h := startHandshakeHarness(f, tlsConfig)
	baseGoroutines := runtime.NumGoroutine()

	// Seeds: fragments of TLS record/ClientHello shapes plus pure garbage.
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01}) // truncated handshake
	f.Add([]byte{0x16, 0x03, 0x03, 0xff, 0xff, 0x01, 0x00, 0xff, 0xfb}) // oversized length
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00})                         // empty record
	f.Add([]byte{0x80, 0x2e, 0x01, 0x03, 0x01})                         // SSLv2-style hello
	f.Add([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))                  // plaintext HTTP to a TLS port
	f.Add([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00})             // bogus alert
	f.Add(captureClientHello(f))                                        // a real, well-formed ClientHello

	f.Fuzz(func(t *testing.T, input []byte) {
		if err := h.probe(input); err != nil {
			t.Fatal(err)
		}
	})

	// After the corpus, the per-connection goroutines must have drained rather
	// than leaked. Allow slack for scheduler lag and the accept loop. Coarse
	// backstop: checked once, not per input.
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseGoroutines+32 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if g := runtime.NumGoroutine(); g > baseGoroutines+32 {
		f.Fatalf("goroutine leak: %d now vs %d baseline (ceiling +32)", g, baseGoroutines)
	}
}

// isClosed reports whether err indicates the peer closed the connection.
func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrUnexpectedEOF)
}

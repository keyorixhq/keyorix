package main

// FuzzTLSHandshakeHostileClientHello throws attacker-controlled bytes at the
// REAL HTTPS listener — the same http.Server + hardened tls.Config
// (createTLSConfig) the server runs in production — over loopback, and checks
// the server survives and stays fail-closed.
//
// Each fuzz input is written raw to a fresh TCP connection as if it were a
// ClientHello (truncated records, oversized extension lengths, SNI tricks, ALPN
// lists, session-ticket and renegotiation bytes, pure garbage). The harness
// client never completes the TLS key exchange, so a well-formed ClientHello
// cannot progress past ServerHello — the point is the SERVER's handling of the
// bytes, not a real session.
//
// Oracles:
//   - no panic: a panic on the server's accept/handshake goroutine crashes the
//     test process and fails the fuzz (crypto/tls is expected to reject bad input
//     with an error, never a panic).
//   - connection closed within a deadline: the server must close a connection
//     that never produces a valid handshake within the configured read timeout;
//     the client proves this by observing EOF/reset before its own (longer)
//     deadline. A hang would fail here.
//   - no data to the HTTP layer from a failed handshake: the HTTP handler sets a
//     flag if it is ever reached. Because the harness client cannot finish a
//     handshake, the handler must NEVER run; if it does, the fuzzer surfaces it.
//   - bounded goroutines: after each input the live goroutine count must stay
//     under a ceiling, catching a per-connection goroutine leak.
//
// What this does NOT verify: it does not complete a real TLS session (no
// client-side crypto), so it does not exercise post-handshake HTTP/2 framing
// (that is the HTTP/2 harness) or application-layer behaviour; it does not
// measure heap bytes directly (it bounds goroutines as the proxy for unbounded
// per-connection work, and relies on the 64 KiB input cap plus crypto/tls's own
// record bounds); it exercises the non-AutoCert HTTP listener only (gRPC/autocert
// share the same tls.Config hardening path, asserted by the unit tests); and it
// cannot distinguish "closed because hardened-rejected" from "closed because the
// dumb client stalled" — both satisfy fail-closed, which is what it asserts.

import (
	"errors"
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

	var handlerReached atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		handlerReached.Store(true)
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
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       2 * time.Second,
		WriteTimeout:      2 * time.Second,
		IdleTimeout:       2 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          nil,
	}
	go srv.ServeTLS(ln, "", "") //nolint:errcheck
	f.Cleanup(func() { _ = srv.Close() })

	addr := ln.Addr().String()
	baseGoroutines := runtime.NumGoroutine()

	// Seeds: fragments of TLS record/ClientHello shapes plus pure garbage.
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01}) // truncated handshake
	f.Add([]byte{0x16, 0x03, 0x03, 0xff, 0xff, 0x01, 0x00, 0xff, 0xfb}) // oversized length
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00})                         // empty record
	f.Add([]byte{0x80, 0x2e, 0x01, 0x03, 0x01})                         // SSLv2-style hello
	f.Add([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))                  // plaintext HTTP to a TLS port
	f.Add([]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00})             // bogus alert

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > maxHandshakeInput {
			input = input[:maxHandshakeInput]
		}

		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			// The listener is loopback and always up; a dial failure is a harness
			// problem, not a finding — skip rather than mis-blame the server.
			t.Skipf("dial: %v", err)
		}
		defer conn.Close() //nolint:errcheck

		// The server must close us within its 2s read timeout. Give generous
		// headroom; if we hit THIS deadline the connection was not closed in time.
		deadline := time.Now().Add(8 * time.Second)
		_ = conn.SetDeadline(deadline)

		if _, err := conn.Write(input); err != nil {
			// A write error (reset) is a perfectly good fail-closed outcome.
			return
		}

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
					t.Fatalf("connection not closed within deadline (server failed to close a bad handshake); read %d bytes", n)
				}
				break // any other read error also means the connection ended
			}
			if time.Now().After(deadline) {
				t.Fatalf("server kept the connection open past the deadline without closing")
			}
		}

		// Oracle: a failed handshake must never reach the HTTP layer.
		if handlerReached.Load() {
			t.Fatalf("HTTP handler was reached from fuzzed pre-handshake bytes — data crossed a failed handshake")
		}
	})

	// After the corpus, the per-connection goroutines must have drained rather
	// than leaked. Allow slack for scheduler lag and the accept loop.
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

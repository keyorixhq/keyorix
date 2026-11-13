package main

// Shared oracle plumbing and self-tests for the REST TLS/HTTP/2 fuzz harnesses
// (FuzzTLSHandshakeHostileClientHello, FuzzHTTP2AbusiveFrames).
//
// Why this file exists: net/http recovers a panic on a connection's goroutine
// (the TLS handshake and the HTTP/2 serverConn run under (*conn).serve's
// recover, and a handler panic is recovered by net/http or x/net/http2), logs
// "http: panic serving ..." / "http2: panic serving ..." to http.Server.ErrorLog
// and closes the connection. A panic therefore does NOT crash the test process;
// the only observable signal is that log line. Both harnesses install a
// panicLog as ErrorLog and fail the input when it has seen one. The tests below
// prove that oracle can fire (a server that panics is reported) and that the h2
// harness's abuse ops reach the limits they are named for.

import (
	"bytes"
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"golang.org/x/net/http2/hpack"
)

// panicLog is an io.Writer for http.Server.ErrorLog that records whether the
// server logged a recovered panic ("http: panic serving" or "http2: panic
// serving"). Safe for concurrent use: net/http logs from connection goroutines.
type panicLog struct {
	mu   sync.Mutex
	seen []string
}

func newPanicLog() *panicLog { return &panicLog{} }

// logger returns a *log.Logger suitable for http.Server.ErrorLog.
func (p *panicLog) logger() *log.Logger { return log.New(p, "", 0) }

func (p *panicLog) Write(b []byte) (int, error) {
	if bytes.Contains(b, []byte("panic serving")) {
		line, _, _ := strings.Cut(string(b), "\n")
		p.mu.Lock()
		p.seen = append(p.seen, line)
		p.mu.Unlock()
	}
	return len(b), nil
}

// err returns a non-nil error naming the first recovered panic seen so far.
func (p *panicLog) err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.seen) == 0 {
		return nil
	}
	return errors.New("server panicked on fuzzed input (recovered by net/http): " + p.seen[0])
}

// waitErr is err with a bounded wait: x/net/http2 queues the RST_STREAM for a
// panicking handler BEFORE it logs, so a client that just saw the reset may be
// a few microseconds ahead of the log line.
func (p *panicLog) waitErr(d time.Duration) error {
	deadline := time.Now().Add(d)
	for {
		if err := p.err(); err != nil {
			return err
		}
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// captureClientHello returns the first TLS record a real crypto/tls client
// writes when it starts a handshake (offering h2), for use as a realistic
// ClientHello seed.
func captureClientHello(t testing.TB) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close() //nolint:errcheck
	defer c2.Close() //nolint:errcheck
	go func() {
		_ = tls.Client(c1, &tls.Config{ServerName: "localhost", NextProtos: []string{"h2"}, InsecureSkipVerify: true}).Handshake() // #nosec G402 -- captures bytes only, no peer
	}()
	_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16<<10)
	n, err := c2.Read(buf)
	if err != nil {
		t.Fatalf("capture ClientHello: %v", err)
	}
	return buf[:n]
}

// TestHostileClientHelloHarness_DetectsServerPanic proves the handshake
// harness's no-panic oracle can fire: a server whose GetCertificate panics
// during the handshake (net/http recovers it, the client just sees EOF) must be
// reported as a failure, while the same ClientHello against a healthy server is
// not.
func TestHostileClientHelloHarness_DetectsServerPanic(t *testing.T) {
	hello := captureClientHello(t)

	t.Run("panicking server is reported", func(t *testing.T) {
		h := startHandshakeHarness(t, &tls.Config{
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { panic("planted handshake panic") },
		})
		err := h.probe(hello)
		if err == nil || !strings.Contains(err.Error(), "panic") {
			t.Fatalf("probe against a panicking GetCertificate returned %v, want a panic error", err)
		}
	})

	t.Run("healthy server is not", func(t *testing.T) {
		certFile, keyFile := writeSelfSignedCert(t, t.TempDir())
		cfg := &config.Config{}
		cfg.Server.HTTP.TLS.Enabled = true
		cfg.Server.HTTP.TLS.CertFile = certFile
		cfg.Server.HTTP.TLS.KeyFile = keyFile
		tlsConfig, err := createTLSConfig(cfg)
		if err != nil {
			t.Fatalf("createTLSConfig: %v", err)
		}
		h := startHandshakeHarness(t, tlsConfig)
		if err := h.probe(hello); err != nil {
			t.Fatalf("probe against a healthy server returned %v", err)
		}
	})
}

// TestHTTP2AbuseHarness_DetectsServerPanic proves the h2 harness's no-panic
// oracle can fire: a handler that panics (recovered by x/net/http2, the client
// just sees a reset) must make run() fail with a panic error, not merely
// "unresponsive".
func TestHTTP2AbuseHarness_DetectsServerPanic(t *testing.T) {
	h := startH2Harness(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("planted handler panic")
	}))
	err := h.run([]byte{0x20}) // any program; the healthy-client ping reaches the handler
	if err == nil || !strings.Contains(err.Error(), "panic") {
		t.Fatalf("run against a panicking handler returned %v, want a panic error", err)
	}
}

// isH2AbuseOp reports whether program byte b selects abuse op n in
// abuseConnection's dispatch (op = b>>4, taken mod 8).
func isH2AbuseOp(b byte, n int) bool { return int(b>>4)%8 == n }

// TestHTTP2AbuseOps_ReachTheirLimit pins that the ops named for oversized
// HEADER blocks and CONTINUATION floods really generate them for EVERY byte
// that selects the op, and that the live server does not treat an op-1 request
// as an ordinary one.
func TestHTTP2AbuseOps_ReachTheirLimit(t *testing.T) {
	// net/http advertises SETTINGS_MAX_HEADER_LIST_SIZE = MaxHeaderBytes + 4096.
	limit := uint32(httpMaxHeaderBytes + 4096)

	t.Run("op1 header list exceeds the limit for every selecting byte", func(t *testing.T) {
		n := 0
		for i := range 256 {
			b := byte(i)
			if !isH2AbuseOp(b, 1) {
				continue
			}
			n++
			var size uint32
			dec := hpack.NewDecoder(1<<30, func(f hpack.HeaderField) { size += f.Size() })
			for _, frag := range bigHeaderFragments(b) {
				if _, err := dec.Write(frag); err != nil {
					t.Fatalf("byte %#02x: hpack decode: %v", b, err)
				}
			}
			if size <= limit {
				t.Errorf("byte %#02x: decoded header list is %d bytes, not above the %d-byte limit", b, size, limit)
			}
		}
		if n == 0 {
			t.Fatal("no program byte selects op 1")
		}
	})

	t.Run("op1 fragments fit the default max frame size", func(t *testing.T) {
		for i := range 256 {
			b := byte(i)
			if !isH2AbuseOp(b, 1) {
				continue
			}
			for _, frag := range bigHeaderFragments(b) {
				if len(frag) > h2AbuseMaxFrame {
					t.Fatalf("byte %#02x: fragment of %d bytes exceeds the %d default SETTINGS_MAX_FRAME_SIZE", b, len(frag), h2AbuseMaxFrame)
				}
			}
		}
	})

	t.Run("op4 sends a flood of continuation frames", func(t *testing.T) {
		most := 0
		for i := range 256 {
			b := byte(i)
			if !isH2AbuseOp(b, 4) {
				continue
			}
			c := continuationFloodCount(b)
			if c < 1 {
				t.Fatalf("byte %#02x: %d continuation frames", b, c)
			}
			most = max(most, c)
		}
		if most < 512 {
			t.Fatalf("largest CONTINUATION flood is %d frames, want >= 512", most)
		}
	})

	t.Run("live server does not answer an op1 request normally", func(t *testing.T) {
		h := startH2Harness(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		for _, b := range []byte{0x10, 0x1f, 0x90, 0x9f} {
			res, err := abuseConnection(h.addr, []byte{b}, 3*time.Second)
			if err != nil {
				t.Fatalf("byte %#02x: %v", b, err)
			}
			t.Logf("byte %#02x: server reaction %+v", b, res)
			if res.sawStatus("204") {
				t.Errorf("byte %#02x: server answered the oversized request with a 204 (header limit not reached)", b)
			}
			if !res.reacted() {
				t.Errorf("byte %#02x: server showed no reaction (no 431, RST_STREAM, GOAWAY or close) within the wait", b)
			}
		}
	})
}

// Package hostile provides shared scaffolding for hostile-SERVER fuzz harnesses
// against the third-party database drivers Keyorix uses against operator-configured
// target databases (internal/dynamic, internal/rotation).
//
// The model is: Keyorix is the CLIENT; the operator-configured target database is
// potentially hostile and replies with attacker-chosen wire bytes. These harnesses
// drive the real driver (as the Keyorix caller drives it) against a loopback server
// whose replies are fuzzer-controlled, and assert sound oracles: no panic escapes the
// driver's documented error path, bounded time, and (where relevant) no credential or
// file is sent to anywhere but the configured host.
//
// Everything runs on a loopback TCP listener — never real network. Loopback (rather
// than net.Pipe) is used deliberately: net.Pipe is synchronous/unbuffered, so a server
// and client that both try to Write at the same instant deadlock; the kernel socket
// buffer on loopback removes that failure mode and keeps the harness, not the driver,
// correct (DISCLOSURE-TRIAGE gate: "harness is itself correct").
package hostile

import (
	"net"
	"testing"
	"time"
)

// Server is a loopback TCP server that hands each accepted connection to a handler.
// The handler plays the hostile server: it may read the client's bytes and must write
// the (fuzzer-controlled) reply, then return. Returning closes the connection.
type Server struct {
	ln   net.Listener
	done chan struct{}
}

// NewServer starts a loopback listener and serves each connection with handler in its
// own goroutine. handler receives the accepted conn; it owns reading/writing and must
// return promptly (it runs under the test's own timeout). Close stops accepting.
func NewServer(tb testing.TB, handler func(net.Conn)) *Server {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	s := &Server{ln: ln, done: make(chan struct{})}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-s.done:
				default:
				}
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				// A hostile server must not be able to wedge the harness: cap every
				// connection's lifetime. The driver call carries its own deadline too.
				_ = c.SetDeadline(time.Now().Add(4 * time.Second))
				handler(c)
			}()
		}
	}()
	return s
}

// Addr is the host:port the driver should connect to.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Host and Port split Addr for DSN construction.
func (s *Server) HostPort() (string, string) {
	h, p, _ := net.SplitHostPort(s.ln.Addr().String())
	return h, p
}

// Close stops the listener.
func (s *Server) Close() {
	close(s.done)
	_ = s.ln.Close()
}

// ReadClientStartup drains a length-prefixed message that has NO type byte (the
// PostgreSQL StartupMessage / SSLRequest / CancelRequest shape: int32 length including
// itself, then length-4 payload bytes). Returns the payload. Bounded by cap.
func ReadClientStartup(c net.Conn, cap int) ([]byte, error) {
	var lenbuf [4]byte
	if _, err := readFull(c, lenbuf[:]); err != nil {
		return nil, err
	}
	n := int(lenbuf[0])<<24 | int(lenbuf[1])<<16 | int(lenbuf[2])<<8 | int(lenbuf[3])
	n -= 4
	if n < 0 || n > cap {
		return nil, errBadLen
	}
	buf := make([]byte, n)
	if _, err := readFull(c, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ReadTypedMessage drains one typed message: 1 type byte + int32 length (incl itself,
// excl type) + length-4 payload. Used to drain client Query ('Q') / parse ('P') etc.
func ReadTypedMessage(c net.Conn, cap int) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := readFull(c, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(hdr[1])<<24 | int(hdr[2])<<16 | int(hdr[3])<<8 | int(hdr[4])
	n -= 4
	if n < 0 || n > cap {
		return hdr[0], nil, errBadLen
	}
	buf := make([]byte, n)
	if _, err := readFull(c, buf); err != nil {
		return hdr[0], nil, err
	}
	return hdr[0], buf, nil
}

func readFull(c net.Conn, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := c.Read(b[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

type lenErr struct{}

func (lenErr) Error() string { return "hostile: bad/overlong length" }

var errBadLen = lenErr{}

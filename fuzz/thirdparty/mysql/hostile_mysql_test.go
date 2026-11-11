// Package mysqlfuzz drives the real github.com/go-sql-driver/mysql client
// against a hostile MySQL server whose entire byte stream is controlled by the
// fuzz input. The goal is to find bugs in the driver itself (parsing of the
// initial handshake, auth-plugin switch/more-data, OK/ERR/EOF packets, the
// LOCAL INFILE request path and the packet framer), reachable through the
// database/sql public API only (mysql.NewConnector + sql.OpenDB + DB.PingContext
// / DB.ExecContext). No Keyorix wrapper is involved, so any finding is a library
// bug.
//
// Threat model: Keyorix connects this driver to operator-configured *target*
// MySQL servers (dynamic-secret engine mints/drops short-lived accounts, see
// internal/dynamic/mysql.go openMySQL -> mysql.NewConnector + sql.OpenDB). A
// malicious or compromised target server controls every wire byte the client
// parses.
//
// ---------------------------------------------------------------------------
// ORACLES (and, explicitly, what each does NOT verify)
// ---------------------------------------------------------------------------
//
//	(a) no panic / no unbounded hang / bounded memory.
//	    - panic ⇒ captured in the Connect goroutine and classified in the fuzz
//	      target (known library-bug sites are swallowed; novel ones fail).
//	    - hang: each Connect runs under an 800ms context AND the fake server
//	      force-closes every socket after a hard deadline (see runHostile), so an
//	      iteration always returns; if even force-close does not unblock it the
//	      run fails with errLibraryHang. Does NOT catch a slow-but-finishing parse.
//	    - memory: the server's declared packet length is CAPPED at maxServerBody
//	      (1 MiB) by the decoder. The driver pre-allocates the declared length up
//	      front (buffer.fill -> make([]byte, ...)), so an uncapped fuzzer could
//	      drive 16 MiB (maxPacketSize) allocations; the cap protects the shared
//	      host. It therefore does NOT exercise the driver's real 16 MiB ceiling;
//	      that amplification is demonstrated/bounded in
//	      TestMySQL_LengthHeaderAmplification.
//
//	(b) canary: the client is configured with a secret password (canaryPassword,
//	    and AllowCleartextPasswords=true so the plaintext secret actually travels
//	    the auth path). The oracle asserts the canary never appears in a returned
//	    error string. Does NOT scan the connector value via reflection (it stores
//	    the password legitimately) nor driver logs (none installed by default).
//
//	(c) echo class: server-controlled text (ERR packet message) surfaced inside an
//	    error is EXPECTED echo, not a bug; the fuzz loop fails only on the canary.
//
//	(d) ignored-read-error: a server that closes mid-packet must make the driver
//	    return an error (ErrInvalidConn / ErrUnexpectedEOF), not a truncated
//	    success. Pinned in TestMySQL_TruncatedMidPacket_Oracle.
//
// An EXTRA oracle specific to this driver, (e) LOCAL INFILE guard, is pinned in
// TestMySQL_LocalInfile_Guard: a hostile server requesting an arbitrary client
// file must be refused by default (AllowAllFiles=false), never read off disk.
package mysqlfuzz

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

const canaryPassword = "s3cr3t-canary-pw-9f3a2b1c"

// maxServerBody caps the per-packet body length the fake server may declare, to
// protect this shared host (the driver pre-allocates the declared length). The
// driver's real ceiling is maxPacketSize = 16 MiB.
const maxServerBody = 1 << 20

// maxWrites caps how many scripted packets the fake server emits, bounding both
// per-iteration time (each post-first packet waits briefly for a client request)
// and memory. A hostile server does not need more than this to exercise parsing.
const maxWrites = 16

var claimTable = [8]int{0, 0, 1, 16, 4096, 1 << 16, 1 << 18, 1 << 20}

// mysqlFrame renders one wire packet: [declaredBody:3 LE][seq:1][payload]. The
// declared body may exceed len(payload) to simulate a short/hostile server.
func mysqlFrame(seq byte, payload []byte, declaredBody int) []byte {
	out := make([]byte, 4+len(payload))
	out[0] = byte(declaredBody)
	out[1] = byte(declaredBody >> 8)
	out[2] = byte(declaredBody >> 16)
	out[3] = seq
	copy(out[4:], payload)
	return out
}

// buildScript decodes the fuzz input into the list of byte blobs the server
// writes. Encoding mirrors the pgx harness:
//
//	op byte: bits 0-1 = action, bits 2-4 = claim selector
//	 action 0/3: packet -> [seq:1][plen:2 BE][payload:plen]
//	 action 1:   raw bytes -> [plen:2 BE][bytes:plen]
//	 action 2:   stop (close)
func buildScript(in []byte) [][]byte {
	r := in
	var out [][]byte
	for len(r) >= 1 {
		op := r[0]
		r = r[1:]
		switch op & 0x03 {
		case 2:
			return out
		case 1:
			if len(r) < 2 {
				return out
			}
			plen := int(binary.BigEndian.Uint16(r[:2]))
			r = r[2:]
			if plen > len(r) {
				plen = len(r)
			}
			out = append(out, append([]byte(nil), r[:plen]...))
			r = r[plen:]
		default:
			if len(r) < 3 {
				return out
			}
			seq := r[0]
			plen := int(binary.BigEndian.Uint16(r[1:3]))
			r = r[3:]
			if plen > len(r) {
				plen = len(r)
			}
			payload := r[:plen]
			r = r[plen:]
			declared := len(payload) + claimTable[(op>>2)&0x07]
			if declared > maxServerBody {
				declared = maxServerBody
			}
			out = append(out, mysqlFrame(seq, payload, declared))
		}
		if len(out) >= maxWrites {
			return out
		}
	}
	return out
}

// syncBuf collects bytes the client sends (used only by the LOCAL INFILE oracle).
type syncBuf struct {
	mu  sync.Mutex
	buf []byte
}

func (s *syncBuf) add(b []byte) {
	s.mu.Lock()
	s.buf = append(s.buf, b...)
	s.mu.Unlock()
}
func (s *syncBuf) bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.buf...)
}

// MySQL is strictly request/response after the server-first handshake: a server
// that blasts unsolicited packets makes the driver's next write fail with
// ErrBusyBuffer (unread buffered data). To exercise handshake/auth/OK parsing
// the server waits (briefly) for the client's request between its own writes:
// writes[0] (the handshake) goes out immediately; before each subsequent write
// serveConn waits up to ~25ms for the client to send its request. Connections
// are released quickly so a hostile input that fails the handshake does not tie
// up the fuzzer across database/sql's internal retries.
//
// fakeServer plays the script as a MySQL server and, crucially, tracks every
// accepted connection so shutdown() can force-close them. Net read/write
// deadlines proved unreliable at bounding a client stuck mid-handshake under
// load (a timing-dependent I/O deadlock in the harness, NOT a library hang —
// isolated replays always complete fast). Force-closing the sockets from the
// harness side is the reliable bound. See runHostile.
type fakeServer struct {
	ln     net.Listener
	writes [][]byte
	cap    *syncBuf
	hold   time.Duration
	mu     sync.Mutex
	conns  []net.Conn
	closed bool
}

func startServer(ln net.Listener, writes [][]byte, cap *syncBuf, hold time.Duration) *fakeServer {
	s := &fakeServer{ln: ln, writes: writes, cap: cap, hold: hold}
	go s.acceptLoop()
	return s
}

func (s *fakeServer) acceptLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = c.Close()
			return
		}
		s.conns = append(s.conns, c)
		s.mu.Unlock()
		go s.serveConn(c)
	}
}

// shutdown closes the listener and every accepted connection, unblocking any
// client (or server) goroutine stuck on a read/write. Idempotent.
func (s *fakeServer) shutdown() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	conns := s.conns
	s.mu.Unlock()
	_ = s.ln.Close()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (s *fakeServer) serveConn(c net.Conn) {
	defer c.Close()
	writes, cap, hold := s.writes, s.cap, s.hold
	var tmp [8192]byte
	for i, w := range writes {
		if i > 0 {
			_ = c.SetReadDeadline(time.Now().Add(25 * time.Millisecond))
			if n, _ := c.Read(tmp[:]); n > 0 && cap != nil {
				cap.add(tmp[:n])
			}
		}
		_ = c.SetWriteDeadline(time.Now().Add(1 * time.Second))
		if _, err := c.Write(w); err != nil {
			return
		}
	}
	// Drain/capture whatever the client sends after the last scripted packet
	// (e.g. LOCAL INFILE content, or a final command) until it closes or hold
	// elapses.
	deadline := 40 * time.Millisecond
	if hold > deadline {
		deadline = hold
	}
	_ = c.SetReadDeadline(time.Now().Add(deadline))
	for {
		n, err := c.Read(tmp[:])
		if n > 0 && cap != nil {
			cap.add(tmp[:n])
		}
		if n > 0 && cap == nil {
			_, _ = io.Discard.Write(tmp[:n])
		}
		if err != nil {
			return
		}
	}
}

// newConfig builds a driver Config pointed at addr with the canary secret and
// cleartext auth enabled so the plaintext secret actually travels the wire path.
func newConfig(addr string) *mysql.Config {
	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = addr
	cfg.User = "canaryuser"
	cfg.Passwd = canaryPassword
	cfg.DBName = "testdb"
	cfg.AllowNativePasswords = true
	cfg.AllowCleartextPasswords = true
	cfg.Timeout = 700 * time.Millisecond
	cfg.ReadTimeout = 500 * time.Millisecond
	cfg.WriteTimeout = 500 * time.Millisecond
	return cfg
}

// errLibraryHang is returned when PingContext does not return even after the
// server has force-closed every socket — the only remaining explanation is a
// CPU-bound loop inside the driver that no I/O event can interrupt. The fuzz
// target treats this as a genuine hang finding.
var errLibraryHang = errors.New("HARNESS: PingContext did not return after force-close (possible library CPU-bound hang)")

// panicErr carries a panic (and its stack) that occurred inside the PingContext
// goroutine back to the caller, so the fuzz target can classify it against
// knownLibPanicSites in the main goroutine. Because PingContext runs in its own
// goroutine (so the harness can force-close on a stall), its panics cannot be
// recovered by the fuzz target directly — they are recovered here and returned.
type panicErr struct {
	val   any
	stack string
}

func (p *panicErr) Error() string { return fmt.Sprintf("panic: %v", p.val) }

const (
	hardBound      = 1200 * time.Millisecond // ctx (800ms) + net timeouts (500ms) should fire first
	postCloseGrace = 600 * time.Millisecond  // after force-close, a healthy client returns at once
)

// runHostile drives the driver through a Ping against a hostile server built
// from script. It GUARANTEES a return within ~hardBound+postCloseGrace by
// force-closing the server sockets if the driver stalls. Returns the error the
// driver produced (nil on success), or errLibraryHang if even force-close did
// not unblock it.
func runHostile(t *testing.T, script []byte) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	s := startServer(ln, buildScript(script), nil, 0)
	defer s.shutdown()

	cfg := newConfig(ln.Addr().String())
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		t.Fatalf("harness: NewConnector failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()

	// Drive the connector's public Connect directly rather than through
	// sql.OpenDB + PingContext: database/sql adds ErrBadConn retries (up to 3
	// handshakes per call) and a background opener, which multiply a hostile
	// input's cost by ~3x and tank fuzz throughput. connector.Connect does
	// exactly one ctx-bounded handshake — the full parsing surface, no retries.
	pingCh := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				pingCh <- &panicErr{val: r, stack: string(debug.Stack())}
			}
		}()
		conn, cerr := connector.Connect(ctx)
		if conn != nil {
			_ = conn.Close()
		}
		pingCh <- cerr
	}()

	select {
	case e := <-pingCh:
		return e
	case <-time.After(hardBound):
		s.shutdown() // force the client to unblock
		select {
		case e := <-pingCh:
			return e
		case <-time.After(postCloseGrace):
			return errLibraryHang
		}
	}
}

// knownLibPanicSites are the stack frames of CONFIRMED go-sql-driver/mysql
// v1.10.1 panics this harness already found, minimised and reproduced
// deterministically (see TestMySQL_*_Reproducer). The fuzz target swallows a
// panic ONLY if its stack hits one of these exact sites, so the fuzzer can keep
// exploring past them; ANY other panic still fails the run as a novel finding.
// Each entry is a real remotely-triggerable DoS (hostile server -> unvalidated
// slice of a server-controlled packet).
var knownLibPanicSites = []string{
	// readHandshakePacket does NO length validation before slicing a
	// server-controlled initial handshake: data[pos:pos+8] (packets.go:209),
	// data[pos:pos+2] capability flags (packets.go:215) and data[pos:pos+12]
	// part-2 (packets.go:256) all panic on a short handshake. One root cause,
	// several manifestation lines; matched by function so every variant counts
	// as the same known finding.
	"mysql.(*mysqlConn).readHandshakePacket",
	// auth mysql_native_password: scramblePassword(authData[:20], ...) with no
	// bounds check on a short AuthSwitchRequest challenge.
	"go-sql-driver/mysql@v1.10.1/auth.go:310",
}

func FuzzMySQLHostileServer(f *testing.F) {
	for _, seed := range mysqlSeeds() {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, script []byte) {
		err := runHostile(t, script)

		if errors.Is(err, errLibraryHang) {
			t.Fatalf("HANG: driver did not return even after the server force-closed all sockets")
		}
		var pe *panicErr
		if errors.As(err, &pe) {
			for _, site := range knownLibPanicSites {
				if strings.Contains(pe.stack, site) {
					return // confirmed library bug, already reported (see reproducer tests)
				}
			}
			t.Fatalf("NEW panic (not a known library bug site): %v\n%s", pe.val, pe.stack)
		}
		if err != nil && strings.Contains(err.Error(), canaryPassword) {
			t.Fatalf("CANARY LEAK: client password appeared in driver error: %q", err.Error())
		}
	})
}

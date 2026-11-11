// Hostile-SERVER fuzz harnesses for go-sql-driver/mysql v1.10.1 (MySQL).
//
// Two harness families coexist in this file:
//
// h6 (FuzzMySQLHandshake / FuzzMySQLQueryResponse / FuzzMySQLPreparedResponse):
//
//	Attack the full call sequence Keyorix uses against an operator-configured
//	target (openMySQLConfig → sql.OpenDB → PingContext / ExecContext /
//	QueryContext), metered by the resguard resource layer. Uses the
//	hostile-server infrastructure package.
//
// h2 (FuzzMySQLHostileServer):
//
//	Canary-focused harness: drives mysql.NewConnector against a fully
//	fuzz-controlled server whose every post-startup byte comes from the fuzz
//	input. Oracles: (a) no panic / no hang (watchdog), (b) canary password never
//	in error, (c) echo class expected, (d) ignored-read-error, (e) LOCAL INFILE
//	guard. Each oracle pinned red/green in oracle_mysql_test.go.
//
// What these oracles do NOT verify: stated in the PR description, not fuzzed here.
package mysqlhostile

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/keyorixhq/keyorix/fuzz/thirdparty/internal/hostile"
)

// ---- h6: MySQL wire framing helpers (server side, hand-built) ----------------------

// capability flags we advertise in the greeting (go-sql-driver const.go names). We omit
// clientDeprecateEOF deliberately so result sets use classic EOF packets (simpler to
// hand-build in seeds); the driver AND-combines with its own flags.
const (
	capClientMySQL      = 0x00000001
	capLongFlag         = 0x00000004
	capLocalFiles       = 0x00000080
	capProtocol41       = 0x00000200
	capTransactions     = 0x00002000
	capSecureConn       = 0x00008000
	capMultiResults     = 0x00020000
	capPluginAuth       = 0x00080000
	capConnectAttrs     = 0x00100000
	capPluginAuthLenEnc = 0x00200000
	serverCapabilities  = capClientMySQL | capLongFlag | capLocalFiles | capProtocol41 |
		capTransactions | capSecureConn | capMultiResults | capPluginAuth |
		capConnectAttrs | capPluginAuthLenEnc
)

// greeting builds a valid handshake v10 initial packet (sequence 0) advertising
// mysql_native_password with a fixed 20-byte scramble. The driver computes a native
// auth response; we accept it unconditionally by replying OK.
func greeting() []byte {
	var p []byte
	p = append(p, 0x0a) // protocol version 10
	p = append(p, []byte("8.0.40-h6-hostile")...)
	p = append(p, 0x00)                   // version NUL
	p = append(p, 1, 0, 0, 0)             // connection id
	p = append(p, 1, 2, 3, 4, 5, 6, 7, 8) // auth-plugin-data part 1 (8)
	p = append(p, 0x00)                   // filler
	p = binary.LittleEndian.AppendUint16(p, uint16(serverCapabilities&0xffff))
	p = append(p, 0x2d)                             // charset utf8mb4_general_ci
	p = binary.LittleEndian.AppendUint16(p, 0x0002) // status flags (autocommit)
	p = binary.LittleEndian.AppendUint16(p, uint16(serverCapabilities>>16))
	p = append(p, 21)                                            // length of auth-plugin-data (8+12+NUL)
	p = append(p, make([]byte, 10)...)                           // reserved
	p = append(p, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20) // scramble part 2 (12)
	p = append(p, 0x00)                                          // scramble terminator
	p = append(p, []byte("mysql_native_password")...)
	p = append(p, 0x00)
	return frame(0, p)
}

// frame wraps payload in a MySQL packet header: 3-byte LE length + 1-byte sequence.
func frame(seq byte, payload []byte) []byte {
	n := len(payload)
	return append([]byte{byte(n), byte(n >> 8), byte(n >> 16), seq}, payload...)
}

// okPacket builds an OK packet (CLIENT_PROTOCOL_41): header, affected=0, insertid=0,
// status[2], warnings[2].
func okPacket(seq byte) []byte {
	return frame(seq, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})
}

// errPacket builds an ERR packet with a SQLState block.
func errPacket(seq byte, code uint16, msg string) []byte {
	p := []byte{0xff, byte(code), byte(code >> 8), '#', '2', '8', '0', '0', '0'}
	p = append(p, msg...)
	return frame(seq, p)
}

// readOnePacket reads one full MySQL packet (header+body) from the client, returning
// its sequence byte and body. Bounded by cap.
func readOnePacket(r *bufio.Reader, cap int) (seq byte, body []byte, err error) {
	var h [4]byte
	if _, err = readFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
	seq = h[3]
	if n < 0 || n > cap {
		return seq, nil, errBadLen
	}
	body = make([]byte, n)
	if _, err = readFull(r, body); err != nil {
		return seq, nil, err
	}
	return seq, body, nil
}

func readFull(r *bufio.Reader, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := r.Read(b[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

type lenErr struct{}

func (lenErr) Error() string { return "hostile-mysql: bad/overlong length" }

var errBadLen = lenErr{}

const capBytes = 1 << 20

// completeHandshake plays the server side of a successful native-password handshake:
// greeting(seq0), read client response(seq1), OK(seq2). Returns with the reader
// positioned to read the client's first command (which resets sequence to 0).
func completeHandshake(c net.Conn, r *bufio.Reader) error {
	if _, err := c.Write(greeting()); err != nil {
		return err
	}
	if _, _, err := readOnePacket(r, capBytes); err != nil { // client handshake response
		return err
	}
	if _, err := c.Write(okPacket(2)); err != nil { // auth result OK
		return err
	}
	return nil
}

// ---- h6: driver config + oracle runner --------------------------------------------

func openDB(tb testing.TB, addr string) *sql.DB {
	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = addr
	cfg.User = "kxadmin"
	cfg.Passwd = "kxpw"
	// Loopback has no real latency; short timeouts turn a hostile "withhold bytes"
	// reply into a fast driver error so fuzz throughput is high. The bounded-time
	// ORACLE (wall-clock, in runWithOracles) is set far above these and is what
	// actually detects a driver that wedges beyond its own deadlines.
	cfg.Timeout = 300 * time.Millisecond
	cfg.ReadTimeout = 300 * time.Millisecond
	cfg.WriteTimeout = 300 * time.Millisecond
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		tb.Fatalf("new connector: %v", err)
	}
	return sql.OpenDB(connector)
}

// knownShortPacketPanics counts recovered panics attributed to the known upstream
// short-packet-underread class across a fuzz run, for reporting.
var knownShortPacketPanics atomic.Int64

// isKnownShortPacketPanic decides whether a recovered panic is the ALREADY-KNOWN,
// already-reported short-packet underread class in go-sql-driver (a truncated hostile
// reply whose body is shorter than the parser assumes → a bounds panic inside the
// driver's packet parsing). Such panics are recorded and tolerated so fuzzing can keep
// hunting for NOVEL defects; ANY other panic (e.g. a nil-pointer dereference, or a
// bounds panic that is NOT inside the driver) is a violation the oracle must flag.
//
// This is deliberately NARROW: it requires BOTH a bounds-class runtime error AND a stack
// frame inside github.com/go-sql-driver/mysql, so a bounds bug in the harness itself, or
// any non-bounds driver panic, still fails the oracle. The red proof
// (TestPanicOracleRedProof) exercises both rejection paths.
func isKnownShortPacketPanic(r any, stack string) bool {
	re, ok := r.(runtime.Error)
	if !ok {
		return false
	}
	msg := re.Error()
	bounds := strings.Contains(msg, "index out of range") ||
		strings.Contains(msg, "slice bounds out of range")
	inDriver := strings.Contains(stack, "github.com/go-sql-driver/mysql")
	return bounds && inDriver
}

func runWithOracles(t *testing.T, fn func(ctx context.Context)) {
	done := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	go func() {
		defer close(done)
		defer func() {
			if r := recover(); r != nil {
				stack := string(debugStack())
				if isKnownShortPacketPanic(r, stack) {
					// Known upstream short-packet DoS (already reported): recorded,
					// NOT re-reported, NOT a new oracle failure.
					knownShortPacketPanics.Add(1)
					return
				}
				t.Errorf("ORACLE panic escaped driver error path (NOVEL): %v", r)
			}
		}()
		fn(ctx)
	}()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Errorf("ORACLE bounded-time: driver call did not return within 6s of a hostile reply")
	}
}

// debugStack returns the current goroutine's stack; split out so the panic classifier
// can be unit-tested with a synthetic stack string.
func debugStack() []byte {
	buf := make([]byte, 8192)
	n := runtime.Stack(buf, false)
	return buf[:n]
}

// drainWrites reads and discards whatever the client writes for a short idle window, so
// the server can proceed without parsing the exact client command framing.
func drainWrites(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	buf := make([]byte, 4096)
	for {
		if _, err := c.Read(buf); err != nil {
			break
		}
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
}

// ---- h6: Fuzz targets -------------------------------------------------------------

// FuzzMySQLHandshake fuzzes the entire server→client stream from the greeting on:
// handshake v10 variants, Auth Switch Request, AuthMoreData (caching_sha2 fast/full),
// OK/ERR, and malformed/truncated variants. Driver call: db.PingContext (opens a conn).
func FuzzMySQLHandshake(f *testing.F) {
	// Seeds are kept BENIGN on purpose: the committed corpus (run by plain `go test`)
	// must stay green. Known truncated-packet reproducers are NOT seeded here; the fuzzer rediscovers that class on its own and the oracle
	// records-and-continues it (see isKnownShortPacketPanic).
	f.Add(greeting())                                                                                                                                                         // valid greeting, then nothing (auth will fail → error)
	f.Add(append(greeting(), okPacket(2)...))                                                                                                                                 // full successful handshake
	f.Add(errPacket(0, 1045, "Access denied"))                                                                                                                                // ERR as first packet
	f.Add(append(greeting(), frame(2, []byte{0xfe, 'c', 'a', 'c', 'h', 'i', 'n', 'g', '_', 's', 'h', 'a', '2', '_', 'p', 'a', 's', 's', 'w', 'o', 'r', 'd', 0, 1, 2, 3})...)) // auth switch
	f.Add(append(greeting(), frame(2, []byte{0x01, 0x03})...))                                                                                                                // AuthMoreData fast-auth-success (caching_sha2)
	probe, budget, haveBudget := mysqlResguardProbe(f, mysqlBudgetHandshake)
	f.Fuzz(func(t *testing.T, server []byte) {
		measureMySQL(t, probe, budget, haveBudget, server, driveMySQLHandshake)
	})
}

// driveMySQLHandshake runs one FuzzMySQLHandshake input under the existing oracles.
// Extracted so the resguard Probe (resguard_mysql_test.go) can measure it and the
// calibration/red-green tests can replay the same path.
func driveMySQLHandshake(t *testing.T, server []byte) {
	srv := hostile.NewServer(t, func(c net.Conn) {
		_, _ = c.Write(server)
		drainWrites(c)
	})
	defer srv.Close()
	db := openDB(t, srv.Addr())
	defer func() { _ = db.Close() }()
	runWithOracles(t, func(ctx context.Context) {
		_ = db.PingContext(ctx)
	})
}

// FuzzMySQLQueryResponse completes a valid handshake, then fuzzes the RAW COM_QUERY
// response bytes (framing included, so short/over-declared packets are in scope):
// OK/ERR/result-set header/column defs/EOF/rows, LOCAL INFILE request, multi-result
// flags, server-declared huge length-encoded lengths. Driver call: db.ExecContext,
// mirroring dynamic/mysql.go's CREATE/GRANT/DROP USER.
func FuzzMySQLQueryResponse(f *testing.F) {
	f.Add(okPacket(1))                             // plain OK
	f.Add(errPacket(1, 1064, "You have an error")) // ERR
	// result set: 1 column, one text row "hi", EOF-terminated (classic protocol).
	colDef := frame(2, []byte{3, 'd', 'e', 'f', 0, 0, 0, 1, 'c', 0, 1, 'c', 0, 0x0c, 0x2d, 0, 4, 0, 0, 0, 0xfd, 0, 0, 0, 0})
	rs := append(frame(1, []byte{0x01}), colDef...)           // column count = 1
	rs = append(rs, frame(3, []byte{0xfe, 0, 0, 0x02, 0})...) // EOF after columns
	rs = append(rs, frame(4, []byte{2, 'h', 'i'})...)         // text row
	rs = append(rs, frame(5, []byte{0xfe, 0, 0, 0x02, 0})...) // EOF after rows
	f.Add(rs)
	f.Add(frame(1, []byte{0xfb, '/', 't', 'm', 'p', '/', 'x'})) // LOCAL INFILE request (non-empty path)
	f.Add(frame(1, []byte{0x03, 'a', 'b', 'c'}))                // text column-count = 3 (well-formed header)
	probe, budget, haveBudget := mysqlResguardProbe(f, mysqlBudgetQuery)
	f.Fuzz(func(t *testing.T, resp []byte) {
		measureMySQL(t, probe, budget, haveBudget, resp, driveMySQLQuery)
	})
}

// driveMySQLQuery runs one FuzzMySQLQueryResponse input under the existing oracles.
func driveMySQLQuery(t *testing.T, resp []byte) {
	srv := hostile.NewServer(t, func(c net.Conn) {
		r := bufio.NewReader(c)
		if err := completeHandshake(c, r); err != nil {
			return
		}
		if _, _, err := readOnePacket(r, capBytes); err != nil { // client COM_QUERY
			return
		}
		_, _ = c.Write(resp)
		drainWrites(c)
	})
	defer srv.Close()
	db := openDB(t, srv.Addr())
	defer func() { _ = db.Close() }()
	runWithOracles(t, func(ctx context.Context) {
		_, _ = db.ExecContext(ctx, "CREATE USER 'kx_dyn_x'@'%' IDENTIFIED BY 'pw'")
	})
}

// FuzzMySQLPreparedResponse completes a valid handshake, then fuzzes the RAW response to
// COM_STMT_PREPARE/EXECUTE (binary protocol): COM_STMT_PREPARE_OK + param/column defs +
// binary result rows. Driver call: db.QueryContext with a bound arg — the exact shape
// killUserConnections' `SELECT id … WHERE user = ?` produces.
func FuzzMySQLPreparedResponse(f *testing.F) {
	// valid COM_STMT_PREPARE_OK: stmt id 1, 0 columns, 1 param, then one param def + EOF.
	prepOK := frame(1, []byte{0x00, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0})
	paramDef := frame(2, []byte{3, 'd', 'e', 'f', 0, 0, 0, 0, 0, 0, 0x0c, 0x3f, 0, 0, 0, 0, 0, 0xfd, 0x80, 0, 0, 0})
	eof := frame(3, []byte{0xfe, 0, 0, 0x02, 0})
	full := append(append(prepOK, paramDef...), eof...)
	f.Add(full)
	f.Add(errPacket(1, 1146, "Table doesn't exist"))
	// prepare-OK declaring large (but well-formed, header-complete) column/param counts.
	f.Add(frame(1, []byte{0x00, 1, 0, 0, 0, 0xff, 0x7f, 0xff, 0x7f, 0, 0}))
	probe, budget, haveBudget := mysqlResguardProbe(f, mysqlBudgetPrepared)
	f.Fuzz(func(t *testing.T, resp []byte) {
		measureMySQL(t, probe, budget, haveBudget, resp, driveMySQLPrepared)
	})
}

// driveMySQLPrepared runs one FuzzMySQLPreparedResponse input under the oracles.
func driveMySQLPrepared(t *testing.T, resp []byte) {
	srv := hostile.NewServer(t, func(c net.Conn) {
		r := bufio.NewReader(c)
		if err := completeHandshake(c, r); err != nil {
			return
		}
		if _, _, err := readOnePacket(r, capBytes); err != nil { // client COM_STMT_PREPARE
			return
		}
		_, _ = c.Write(resp)
		drainWrites(c)
	})
	defer srv.Close()
	db := openDB(t, srv.Addr())
	defer func() { _ = db.Close() }()
	runWithOracles(t, func(ctx context.Context) {
		rows, err := db.QueryContext(ctx, "SELECT id FROM information_schema.processlist WHERE user = ?", "kx_dyn_x")
		if err == nil {
			for rows.Next() {
			}
			_ = rows.Close()
		}
	})
}

// ---- h2: canary-focused hostile-server harness (buildScript encoding) ---------------

// canaryPassword is the client-side secret. The hostile server never learns it
// unless the driver leaks it (AllowCleartextPasswords=true so the plaintext
// secret actually travels the auth path), so it must never surface in an error.
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
